# Prompt 08: pierwszy boot Fedora-Lab

## Cel etapu

Prompt 08 połączył przygotowany wcześniej dysk Fedora-Lab z minimalnym provisioningiem systemu gościa. Celem było przygotowanie danych cloud-init, wykonanie pierwszego kontrolowanego bootu oraz uzyskanie wiarygodnej obserwowalności guest OS bez instalowania Luny, Codexa ani środowiska developerskiego.

Ten etap był pierwszym momentem, w którym Forge nie tylko zarządzał definicją i storage VM, lecz również sprawdzał rezultat wewnątrz uruchomionego systemu.

## Architektura

Łańcuch zaufania i zapisu wygląda następująco:

```text
verified Fedora Cloud Base artifact
  → immutable qcow2 base volume w libvirt
  → writable qcow2 overlay konkretnej instancji Fedora-Lab
  → VM uruchamiana przez libvirt/KVM
```

Zweryfikowany obraz Fedory w katalogu użytkownika pozostaje źródłem zaufania. Systemowy QEMU nie używa go bezpośrednio. Libvirt przechowuje osobny bazowy volume `forge-base-fedora-44.qcow2`, a właściwym dyskiem VM jest zapisywalny overlay.

Provisioning jest dostarczany przez osobny NoCloud seed ISO. Seed nie modyfikuje relacji base/overlay i jest podpinany jako read-only CD-ROM. Ostateczna instancja używa:

```text
vda: fedora-lab.rebuild.qcow2
     backing → forge-base-fedora-44.qcow2

sda: fedora-lab-rebuild-seed.iso
     read-only NoCloud CD-ROM
```

Libvirt/KVM odpowiada za lifecycle domeny i urządzenia. QEMU Guest Agent oraz SSH pełnią różne role:

- QGA jest infrastrukturalnym kanałem telemetrycznym.
- SSH jest command plane do jawnie ograniczonych odczytów wewnątrz guest OS.

## Cloud-init

Cloud-init tworzy minimalną konfigurację Fedora-Lab:

- hostname `fedora-lab`,
- użytkownik `forge`,
- logowanie wyłącznie dedykowanym publicznym kluczem SSH,
- `lock_passwd: true`,
- `ssh_pwauth: false`,
- `disable_root: true`,
- brak ustawionego hasła,
- brak `sudo`, grupy `wheel` i `NOPASSWD`,
- instalacja oraz uruchomienie `qemu-guest-agent`.

Ważna korekta polityki pojawiła się podczas review. Początkowa kombinacja z klasycznym `sudo: ALL=(ALL) ALL` była bezużyteczna: konto miało zablokowane hasło, więc nie mogło uwierzytelnić się przed `sudo`. Fedora-Lab nie jest profilem YOLO, dlatego ostatecznie użytkownik `forge` nie otrzymuje żadnych uprawnień sudo. Provisioning wymagający uprawnień wykonuje sam cloud-init w swoim uprzywilejowanym kontekście.

Seed zawiera tylko `user-data` i `meta-data`. Nie zawiera prywatnego klucza, hasła ani innego sekretu.

## QEMU Guest Agent

Sama instalacja pakietu `qemu-guest-agent` wewnątrz Fedory nie wystarczyła. Pierwsza domena nie miała urządzenia komunikacyjnego po stronie hypervisora, dlatego libvirt zwracał:

```text
QEMU guest agent is not configured
```

Rozwiązaniem było dodanie kanału do deklaratywnego `DomainSpec` Fedora-Lab:

```xml
<channel type='unix'>
  <target type='virtio' name='org.qemu.guest_agent.0'/>
</channel>
```

Forge waliduje, że istnieje dokładnie jeden taki kanał. Po rebuildzie target otrzymał stan `connected`, a `guest-ping` zaczął odpowiadać poprawnie.

QGA nie jest jednak używany do uruchamiania arbitralnych poleceń. Próba wykonania `cloud-init` przez RPC `guest-exec` zakończyła się `Permission denied`. Nie poluzowaliśmy SELinux, nie włączyliśmy `virt_qemu_ga_run_unconfined`, nie wyłączyliśmy blacklist RPC i nie zmieniliśmy konfiguracji agenta, aby wymusić arbitrary command execution. Zamiast tego `guest-exec` został całkowicie usunięty z architektury Forge.

## Failure modes i błędne założenia

### Niepoprawny XML storage volume seeda

Pierwsza próba utworzenia `fedora-lab-seed.iso` zatrzymała się przed mutacją domeny. Generator dodał do volume element `<description>`, którego lokalny schemat `storagevol.rng` nie dopuszczał. Libvirt zgłosił błąd kolejności/zawartości i oczekiwał poprawnego `<target>`.

Generator został ograniczony do minimalnego XML zgodnego ze schematem:

```xml
<volume type='file'>
  <name>fedora-lab-seed.iso</name>
  <capacity unit='bytes'>...</capacity>
  <allocation unit='bytes'>0</allocation>
  <target>
    <format type='raw'/>
  </target>
</volume>
```

Capacity pochodzi z rzeczywistego rozmiaru wygenerowanego ISO. XML został sprawdzony przez `virt-xml-validate` ze schematem `storagevol`.

### Brak kanału guest-agent

Po naprawie seeda VM wystartowała i otrzymała lease DHCP, ale QGA pozostawał niedostępny, a pierwsze próby SSH nie potwierdziły jeszcze uwierzytelnienia. Błędne założenie brzmiało: „instalacja pakietu guest-agent wystarczy”. Brakowało kanału virtio w XML domeny.

### `guest-exec` i polityka bezpieczeństwa guest OS

Po dodaniu kanału `guest-ping` działał, lecz próba:

```text
guest-exec /usr/bin/cloud-init
```

została zablokowana przez politykę bezpieczeństwa guest OS jako `Permission denied`. To nie był problem do obejścia. Był to sygnał, że QGA został użyty w niewłaściwej roli. Decyzją architektoniczną było pozostawienie QGA jako telemetry/control plane i przeniesienie obserwacji systemu do SSH.

### Timeout SSH i zaszyfrowany klucz

Pierwsze próby SSH dochodziły do wymiany host key, ale nie zwracały wyników zdalnych poleceń. Sam zapis host key został początkowo zbyt łatwo uznany za oznakę działającego SSH. W rzeczywistości nie potwierdza on uwierzytelnienia użytkownika.

Dedykowany prywatny klucz Forge był zaszyfrowany i nie był załadowany do `ssh-agent`. `BatchMode=yes` poprawnie uniemożliwił interaktywny prompt o passphrase, więc obserwacja kończyła się typed timeoutem zamiast wisieć bez końca.

Po świadomym wykonaniu przez użytkownika:

```bash
ssh-add ~/.ssh/forge_ed25519
```

SSH użył klucza z agenta i jednoznacznie potwierdził authentication. Forge nie otrzymał i nie przechowuje passphrase.

## Finalny flow obserwowalności

```text
Domain Running
  → DHCP/IP przez libvirt
  → QGA guest-ping
  → SSH jako forge z BatchMode=yes i timeoutem
  → cloud-init status --long
  → id
  → hostname
```

Statusy są typed i nie wynikają z domysłów:

- `DomainBootStatus`,
- `DhcpLeaseStatus`,
- `GuestAgentStatus`,
- `SshStatus`,
- `CloudInitStatus`.

Pojawienie się host key nie oznacza `SshStatus::Authenticated`. Authentication jest potwierdzane dopiero przez wykonanie zdalnych poleceń i odebranie oczekiwanych wyników. Wszystkie oczekiwania mają skończone timeouty.

## Finalny potwierdzony rezultat

```text
DomainBootStatus:  Running
DHCP/IP:           192.168.122.147
GuestAgentStatus:  Available
SshStatus:         Authenticated
CloudInitStatus:   Done
user:              forge (uid=1000)
hostname:          fedora-lab
datasource:        DataSourceNoCloud [seed=/dev/sr0]
```

Cloud-init zakończył się bez błędów i bez recoverable errors. Seed został poprawnie rozpoznany jako NoCloud z read-only CD-ROM `/dev/sr0`.

## Najważniejsze wnioski security

- QGA jest telemetry/control plane, a nie furtką do arbitrary command execution.
- SSH jest osobnym command plane z dedykowaną tożsamością `forge`.
- Fedora-Lab nie ma password login, root SSH, sudo ani `NOPASSWD`.
- Seed otrzymuje wyłącznie klucz publiczny w czasie działania Forge. Repo nie przechowuje materiału klucza, a prywatny klucz nigdy nie trafia do seeda, VM ani repo.
- Forge nie zna passphrase klucza. Dostęp do odszyfrowanego klucza zapewnia świadomie przygotowany `ssh-agent` użytkownika.
- Host security oraz guest SELinux nie są luzowane dla wygody automatyzacji.
- Brak jednoznacznego sygnału jest raportowany jako `Unknown`, `TimedOut` albo `AuthenticationFailed`, nigdy jako sukces.

## Najważniejsze komendy

Walidacja kodu:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

Planowanie i lifecycle:

```bash
forge vm boot fedora-lab --dry-run
forge vm boot fedora-lab
forge vm rebuild fedora-lab --dry-run
forge vm rebuild fedora-lab
forge vm list
```

Read-only diagnostyka libvirt:

```bash
virsh -c qemu:///system dominfo fedora-lab
virsh -c qemu:///system domifaddr fedora-lab --source lease
virsh -c qemu:///system qemu-agent-command fedora-lab '{"execute":"guest-ping"}'
virsh -c qemu:///system domblklist fedora-lab --details
virsh -c qemu:///system vol-list default --details
```

Klucz i końcowa obserwacja SSH:

```bash
ssh-add ~/.ssh/forge_ed25519
ssh -o BatchMode=yes forge@192.168.122.147 \
  'cloud-init status --long; id; hostname'
```

## Co istnieje po Prompt 08

- działająca persistent VM Fedora-Lab,
- trusted Fedora base oraz zapisywalny qcow2 overlay,
- provisioning NoCloud/cloud-init,
- użytkownik `forge` z SSH key-only,
- działający kanał i pakiet QEMU Guest Agent,
- read-only obserwacja guest OS przez SSH,
- typed observability z jawnymi timeoutami,
- bezpieczny lifecycle boot oraz rebuild zachowujący starą generację zasobów.

## Czego jeszcze nie ma

- Luny ani Codexa wewnątrz VM,
- profilu YOLO i jego odrębnej polityki uprawnień,
- cleanupu starego `fedora-lab.prepare.qcow2` i `fedora-lab-seed.iso`,
- własnego GUI,
- dalszego etapu Prompt 09.
