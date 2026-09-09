# Forge V2.5 — Quick Start

Ten dokument jest najkrótszą praktyczną drogą od świeżej Fedory do działających maszyn w Forge V2.5.

Nie musisz znać architektury Forge, manifestów, generation IDs ani wewnętrznego modelu recovery, żeby zacząć. Jeżeli wszystko działa normalnie, wykonujesz kolejne kroki i korzystasz z VM.

Jeżeli Forge zatrzyma operację, zgłosi `RecoveryRequired`, `Conflict`, `Orphaned`, `Interrupted` albo inną sytuację wymagającą naprawy — nie próbuj ręcznie poprawiać plików lub zasobów libvirt. Wtedy przejdź do [FORGE_V2_5_USER_GUIDE.md](FORGE_V2_5_USER_GUIDE.md). Konfigurację hosta opisuje [FEDORA_SETUP.md](FEDORA_SETUP.md).

---

# 1. Zanim zaczniesz

Forge V2.5 działa na Fedorze i korzysta z KVM/QEMU, libvirt, `qemu:///system`, standardowego storage pool `default` oraz standardowej sieci libvirt `default` tam, gdzie profil jej potrzebuje. Rust/Cargo są potrzebne do zbudowania Forge ze źródeł.

Przyda się również `virt-manager`, ponieważ Kali, Fedora Workstation i Whonix są normalnymi graficznymi maszynami, które konfigurujesz samodzielnie.

Forge nie wymaga wyłączania SELinux ani firewalla. Nie konfiguruj dla Forge szerokiego `NOPASSWD sudo`. Jeżeli system poprosi o standardowe hasło PolicyKit podczas operacji libvirt, jest to normalne.

Pełne przygotowanie świeżej Fedory: [FEDORA_SETUP.md](FEDORA_SETUP.md).

---

# 2. Zainstaluj Forge

Forge V2.5.0 jest obecnie instalowany ze źródeł.

```bash
git clone https://github.com/gogu-glogowski/Forge-v2.git
cd Forge-v2
git checkout v2.5.0
cargo build --release -p forge-cli
mkdir -p ~/.local/bin
install -m 755 target/release/forge ~/.local/bin/forge
```

Sprawdź instalację:

```bash
command -v forge
forge --help
forge doctor
```

## STOP, jeśli `doctor` pokazuje problem

Nie twórz jeszcze VM. Najpierw popraw problem wskazany przez `doctor`, szczególnie KVM, libvirt, storage pool `default` i wymagane elementy hosta. `forge doctor` diagnozuje host — nie naprawia go po cichu.

Jeżeli wszystko jest gotowe:

```bash
forge profile list
forge image list
```

Teraz możesz wybrać system.

---

# 3. Kali — najszybszy start

## Krok 1 — pobierz i zweryfikuj Kali

```bash
forge image inspect kali
forge image fetch kali
forge image inspect kali
```

Pierwsze pobranie i weryfikacja mogą potrwać. Forge weryfikuje oficjalny artefakt Kali i przygotowuje go do dalszego użycia.

## Krok 2 — utwórz VM

Nazwijmy pierwszą maszynę `kali-1`.

```bash
forge vm plan kali-lab kali-1
forge vm create kali-lab kali-1 --dry-run
forge vm create kali-lab kali-1
```

Pierwsze tworzenie może potrwać, ponieważ Forge wykonuje weryfikację i przygotowuje współdzieloną bazę.

## Krok 3 — uruchom

```bash
forge vm start kali-1
```

Otwórz VM w `virt-manager`.

## TERAZ PRACUJESZ RĘCZNIE W KALI

Od tego momentu konfiguracja systemu należy do Ciebie. Możesz zalogować się zgodnie z dokumentacją obrazu Kali, ustawić lub zmienić swoje hasło, zaktualizować Kali, zainstalować swoje narzędzia i skonfigurować system pod siebie.

Forge nie loguje się do guest OS za Ciebie i nie konfiguruje automatycznie Twojego konta.

## Krok 4 — normalne wyłączenie

```bash
forge vm shutdown kali-1
forge vm status kali-1
```

Gotowe. Masz persistent VM Kali zarządzaną przez Forge.

---

# 4. Fedora Workstation — instalacja krok po kroku

Fedora Workstation działa inaczej niż Kali. Forge pobiera i weryfikuje oficjalne ISO oraz przygotowuje VM, ale Fedorę instalujesz samodzielnie, graficznie przez Anacondę.

## Krok 1 — pobierz Fedorę

```bash
forge image fetch fedora-workstation
forge image inspect fedora-workstation
```

## Krok 2 — przygotuj instalację

```bash
forge image prepare fedora-workstation
forge image prepare-status fedora-workstation
forge image prepare-start fedora-workstation
```

Teraz otwórz przygotowaną VM w `virt-manager`.

## TERAZ ODKŁADASZ TERMINAL — RĘCZNIE W FEDORZE

Przejdź normalną instalację Fedora Workstation w Anacondzie. Ustaw świadomie opcje instalacji, użytkownika, login, hasło, język, strefę czasową i inne potrzebne ustawienia. Zainstaluj system na przygotowanym przez Forge dysku.

Po zakończeniu instalacji normalnie wyłącz VM, gdy dojdziesz do granicy wymaganej przez Forge.

## WRACAMY DO TERMINALA

```bash
forge image prepare-confirm-installed fedora-workstation
```

Forge może wyświetlić dokładną komendę `qemu-img check`. Jeżeli ją wyświetli: otwórz drugi terminal, uruchom dokładnie podaną komendę, sprawdź jej poprawne zakończenie, wróć do Forge i wpisz `CHECKED` tylko wtedy, gdy rzeczywiście wykonałeś sprawdzenie. Nie podstawiaj własnej ścieżki do obrazu.

## Krok 3 — uruchom już zainstalowaną Fedorę

```bash
forge image prepare-continue fedora-workstation
```

Otwórz ją ponownie w `virt-manager`.

## ZNOWU RĘCZNIE W FEDORZE

Przejdź GNOME Initial Setup, jeżeli się pojawi. Zaloguj się, sprawdź działanie systemu i ustaw rzeczy, które mają być punktem startowym dla przyszłych VM: podstawowe ustawienia GNOME, język, preferencje, potrzebne repozytoria i oprogramowanie.

**WAŻNE:** Forge V2.5 nie sanitizuje automatycznie tej instalacji. To, co pozostawisz w tej Fedorze przed promocją, może zostać odziedziczone przez późniejsze VM Fedora Workstation — w tym konta, hasła, ustawienia, oprogramowanie, repozytoria i konfiguracja GNOME. Skonfiguruj bazową instalację świadomie.

## Krok 4 — potwierdź działający system

```bash
forge image prepare-confirm-graphical fedora-workstation
```

Następnie normalnie wyłącz przygotowywaną Fedorę.

## Krok 5 — utwórz bazę Fedora Workstation

```bash
forge image prepare-promote fedora-workstation
forge image prepare-status fedora-workstation
```

Jeżeli Forge ponownie wymaga dokładnego `qemu-img check`, wykonaj podaną przez niego komendę i potwierdź ją zgodnie z instrukcją.

## Krok 6 — utwórz normalną Fedorę

```bash
forge vm plan fedora-workstation fedora-1
forge vm create fedora-workstation fedora-1
forge vm start fedora-1
```

Otwórz `fedora-1` w `virt-manager`. Gotowe.

---

# 5. Whonix — Gateway + Workstation

Whonix w Forge składa się z dwóch współpracujących VM:

```text
whonix-gateway
        ↓
whonix-workstation
```

W V2.5 używaj dokładnie nazw `whonix-gateway` i `whonix-workstation`.

## Krok 1 — Gateway

```bash
forge vm plan whonix-gateway whonix-gateway
forge vm create whonix-gateway whonix-gateway
```

Pierwsze tworzenie może potrwać długo. Forge wykonuje acquisition, weryfikację oraz pracę na dużych artefaktach Whonixa.

## Krok 2 — Workstation

```bash
forge vm plan whonix-workstation whonix-workstation
forge vm create whonix-workstation whonix-workstation
```

## Krok 3 — uruchom Whonixa

Najpierw Gateway, potem Workstation:

```bash
forge vm start whonix-gateway
forge vm start whonix-workstation
forge vm status whonix-gateway
forge vm status whonix-workstation
```

Otwórz VM w `virt-manager`.

## TERAZ RĘCZNIE W WHONIX

Forge przygotował host-side VM i ich topologię. Konfigurację samego Whonixa wykonujesz wewnątrz guest OS: przejdź oficjalny Whonix first-run, wykonaj wymagane kroki konfiguracyjne, aktualizacje i własne ustawienia. W sprawach bezpieczeństwa samego Whonixa korzystaj z oficjalnej dokumentacji Whonix.

## Wyłączanie Whonixa

Najpierw Workstation, potem Gateway:

```bash
forge vm shutdown whonix-workstation
forge vm shutdown whonix-gateway
```

Gotowe.

---

# 6. Codzienne używanie Forge

```bash
forge vm list
forge vm status <instance>
forge vm start <instance>
forge vm shutdown <instance>
```

Awaryjne twarde zatrzymanie:

```bash
forge vm stop <instance> --force
```

`--force` traktuj jak odcięcie zasilania. Nie używaj go jako normalnego sposobu wyłączania VM.

---

# 7. Clone

```bash
forge vm clone <source> <target> --dry-run
forge vm clone <source> <target>
```

Nowa maszyna jest osobnym persistent VM. Forge nie wykonuje automatycznej regeneracji guest identity ani personalizacji systemu wewnątrz klona.

---

# 8. Fresh

Dla profili obsługujących Fresh:

```bash
forge vm fresh <instance> --dry-run
forge vm fresh <instance>
```

Fresh oznacza nową generację VM z zaufanej bazy. Nie oznacza `dnf upgrade`, `apt upgrade`, aktualizacji dystrybucji ani aktualizacji współdzielonej bazy. Aktualizacje systemu wewnątrz guest OS wykonujesz samodzielnie.

---

# 9. Delete

Normalne usunięcie VM:

```bash
forge delete <instance>
```

Jeżeli VM działa, najpierw normalnie ją wyłącz:

```bash
forge vm shutdown <instance>
forge delete <instance>
```

Jeżeli świadomie chcesz wymusić destrukcyjną operację na działającej dokładnie zidentyfikowanej VM:

```bash
forge delete <instance> --force
```

Forge sprawdza własność zasobów przed usunięciem i chroni współdzielone bazy. Jeżeli nie potrafi jednoznacznie udowodnić, co należy do danej VM, powinien odmówić operacji zamiast zgadywać.

---

# 10. Forge zatrzymał operację — co teraz?

Najważniejsza zasada: **nie naprawiaj ręcznie stanu Forge tylko dlatego, że nazwa pliku lub VM wygląda znajomo.**

Jeżeli zobaczysz `RecoveryRequired`, `Conflict`, `Orphaned`, `Interrupted`, problem z ownership, backing chain, niezgodność domeny albo przerwaną operację create/preparation, przejdź do [FORGE_V2_5_USER_GUIDE.md](FORGE_V2_5_USER_GUIDE.md).

Forge celowo zatrzymuje operację, kiedy nie może bezpiecznie udowodnić stanu. To jest mechanizm bezpieczeństwa, a nie powód do ręcznego kasowania plików.

---

# 11. Najkrótsza ściąga

## Kali

```text
forge image fetch kali
        ↓
forge vm create kali-lab kali-1
        ↓
forge vm start kali-1
        ↓
[RĘCZNIE skonfiguruj Kali]
        ↓
GOTOWE
```

## Fedora Workstation

```text
forge image fetch fedora-workstation
        ↓
forge image prepare fedora-workstation
        ↓
forge image prepare-start fedora-workstation
        ↓
[RĘCZNIE: Anaconda + konto + hasło]
        ↓
shutdown
        ↓
forge image prepare-confirm-installed fedora-workstation
        ↓
forge image prepare-continue fedora-workstation
        ↓
[RĘCZNIE: sprawdź Fedora + GNOME Initial Setup]
        ↓
forge image prepare-confirm-graphical fedora-workstation
        ↓
shutdown
        ↓
forge image prepare-promote fedora-workstation
        ↓
forge vm create fedora-workstation fedora-1
        ↓
forge vm start fedora-1
        ↓
GOTOWE
```

## Whonix

```text
forge vm create whonix-gateway whonix-gateway
        ↓
forge vm create whonix-workstation whonix-workstation
        ↓
forge vm start whonix-gateway
        ↓
forge vm start whonix-workstation
        ↓
[RĘCZNIE: Whonix first-run i konfiguracja]
        ↓
GOTOWE
```

---

# 12. Gdzie czytać dalej?

Jeżeli potrzebujesz tylko uruchomić Forge, ten Quick Start powinien wystarczyć.

Pełne zachowanie CLI, recovery, obrazy, ownership i bezpieczne usuwanie: [FORGE_V2_5_USER_GUIDE.md](FORGE_V2_5_USER_GUIDE.md).

Przygotowanie świeżego hosta Fedora: [FEDORA_SETUP.md](FEDORA_SETUP.md).

Forge ma być prosty podczas normalnego używania. Skomplikowane mechanizmy istnieją przede wszystkim po to, żeby Forge wiedział, kiedy **nie powinien** wykonać niebezpiecznej operacji.
