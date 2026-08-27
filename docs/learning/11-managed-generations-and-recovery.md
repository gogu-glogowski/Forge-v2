# Prompt 11: managed generations i recovery lifecycle

## Cel etapu

Prompt 11 rozszerzył trwały state z modelu jednej generacji do pełnego lifecycle wielu generacji Fedora-Lab. Forge potrafi teraz przypisać ownership zasobom już w chwili ich utworzenia, przygotować nową generację jako `Preparing`, zachować poprzednią jako `Retained`, rozpoznać nieudane próby jako `Failed` i bezpiecznie przejść przez przerwany rebuild.

Zakres etapu objął:

- managed generations,
- ownership od momentu utworzenia zasobu,
- statusy `Active`, `Preparing`, `Retained`, `Failed` i `Cleaned`,
- managed rebuild z trwałą granicą recovery,
- jawne, fail-closed recovery finalize,
- przygotowanie cleanupu wyłącznie dla zasobów `Retained Owned`.

Najważniejsza zmiana nie polega na tym, że każda VM ma być często wymieniana. Fedora-Lab nie jest disposable z definicji. Może działać długo na jednej stabilnej generacji `Active`. Generation lifecycle uruchamia się dopiero wtedy, gdy użytkownik świadomie wykonuje rebuild lub replace.

## Stała VM a disposable generation

Nazwa domeny, UUID domeny i jej rola mogą pozostać stałe, mimo że zmieniają się zasoby konkretnej instancji systemu:

```text
Fedora-Lab jako trwała VM
  └── Active generation
        ├── writable overlay
        ├── NoCloud seed
        └── shared base jako chroniona zależność
```

Disposable może być konkretna generacja overlay + seed, ale nie cała Fedora-Lab. Dopóki nie rozpoczynamy rebuilda, nie powstaje `Preparing`, nie ma switchu i nie ma powodu uruchamiać cleanup lifecycle.

To rozróżnienie zapobiega niebezpiecznemu założeniu, że „lab” oznacza zasób, który można automatycznie skasować i odtworzyć.

## Nowy state layout

State Fedora-Lab ma teraz katalog domeny:

```text
~/.local/share/forge/state/fedora-lab/
├── index.json
└── generations/
    ├── <generation-a>.json
    ├── <generation-b>.json
    └── <generation-c>.json
```

`index.json` jest małym, mutowalnym punktem koordynacji. Przechowuje:

- schema version,
- nazwę i UUID domeny,
- `active_generation_id`,
- listę generacji i ich aktualne statusy,
- ścieżki do odpowiadających im manifestów.

Pliki `generations/<generation-id>.json` są immutable generation manifests. Rejestrują historyczną tożsamość generacji i jej zasobów: domain identity, pool identity, role volumes, libvirt keys, paths, formaty, capacity i backing relationship. Status operacyjny może później zmienić się w indeksie, ale manifest nie jest przepisywany tak, aby udawać inną historię.

Podział ma znaczenie dla crash safety. Jedna atomowa wymiana `index.json` może zmienić jednocześnie `A: Active → Retained`, `C: Preparing → Active` i `active_generation_id = C`. Nie istnieje stan pośredni wymagający dwóch niezależnych zapisów statusu.

## Migracja single-generation state

Prompt 10 używał pojedynczego manifestu domeny. Migracja do nowego layoutu jest lossless:

1. stary manifest musi być poprawny i mieć status `Active`,
2. jego niezmieniona treść trafia do `generations/<generation-id>.json`,
3. dopiero potem atomowo publikowany jest `index.json`,
4. stary plik pozostaje jako źródło recovery zamiast być automatycznie usuwany.

Samo wykrycie starego state nie jest auto-adoption. Migracja odbywa się w kontrolowanym workflow, a zasoby legacy bez historycznego manifestu ownership nadal pozostają `Unmanaged`.

## Statusy generacji

### Preparing

Generacja ma już trwały ownership i własne zasoby, ale nie została jeszcze uznana za działającą `Active`. `Preparing` jest również trwałą granicą recovery. Jej obecność blokuje kolejny managed rebuild i cleanup.

### Active

Dokładnie jedna generacja wskazywana przez `active_generation_id`. Musi odpowiadać generacji jednoznacznie obserwowanej w persistent libvirt state. Invariant indeksu odrzuca zero lub więcej niż jedną `Active`.

### Retained

Poprzednia poprawna generacja zachowana po udanym switchu. Dopiero `Retained`, pełny durable ownership i świeży dowód braku referencji mogą uczynić jej disposable zasoby kandydatami do cleanupu.

### Failed

Generacja, której przygotowanie nie zakończyło się bezpiecznym switchem. `Failed` nie jest synonimem „można usunąć”. Nie trafia automatycznie do cleanup candidates.

### Cleaned

Stan indeksu oznaczający, że disposable resources wcześniej udowodnionej generacji `Retained` zostały usunięte. Przejście do niego nie jest dostępne dla `Active`, `Preparing` ani `Failed`.

## Główna zasada ownership

```text
create → own → activate → retain → prove → delete
```

Ownership nie może zostać dopisany po fakcie na podstawie podobnej nazwy. Forge najpierw tworzy zasób w kontrolowanym workflow, zapisuje jego dokładną tożsamość w immutable manifest, a dopiero potem może go aktywować. Po zastąpieniu zasób staje się `Retained`, lecz nadal nie jest automatycznie kasowany. Przed delete trzeba ponownie udowodnić identity, status i brak referencji.

Druga reguła pozostaje bezwzględna:

```text
Unmanaged legacy != cleanup candidate
```

## Managed rebuild

Punkt wyjścia pierwszego managed rebuilda wyglądał tak:

```text
A = Active
```

Forge wygenerował losowy Generation ID dla C, a nazwy jej overlay i seeda zostały związane z tym ID. Przebieg był następujący:

1. zaplanowanie C bez mutacji,
2. utworzenie i walidacja własnego overlay oraz NoCloud seeda C,
3. zapis immutable manifestu C jako `Preparing`,
4. atomowa publikacja C w indeksie przy zachowaniu A jako `Active`,
5. graceful shutdown starego guest OS,
6. ponowna walidacja stanu i switch persistent domain XML,
7. boot oraz obserwowalność DHCP, QGA, SSH i cloud-init,
8. dopiero po pełnym sukcesie atomowy transition A/C.

Shared base nie należy do żadnej pojedynczej generacji jako disposable resource. Jest rejestrowany jako chroniona zależność, a overlay C musi mieć dokładny backing do tego base. Cleanup nigdy nie może objąć `SharedBase`.

Najważniejszy porządek brzmi:

```text
durable ownership przed persistent domain switch
```

Gdyby switch nastąpił wcześniej, przerwany proces zostawiłby działającą generację, której Forge nie potrafiłby bezpiecznie przypisać.

## Pierwszy failure: shutdown już wyłączonej domeny

Pierwsza próba managed rebuilda zatrzymała się, ponieważ orkiestracja próbowała wykonać graceful shutdown mimo że domena była już `shut off`. Sam shutdown jako operacja był rozsądny, ale jego implementacja nie była idempotentna w tym punkcie workflow.

Poprawka wprowadziła jawny wynik `AlreadyShutoff`. Stan `Running` nadal prowadzi do graceful shutdown i oczekiwania z finite timeout, natomiast `Shutoff` jest poprawnym, osiągniętym stanem wejściowym. Stany niejednoznaczne, takie jak paused, crashed lub unknown, nadal fail closed.

Lekcja jest szersza: idempotencja nie może istnieć wyłącznie na poziomie publicznej komendy. Musi obowiązywać także wewnątrz orkiestracji, na granicach poszczególnych kroków, ponieważ proces może zostać wznowiony po częściowym wykonaniu.

## Crash/recovery boundary

Najważniejszy scenariusz recovery wyglądał tak:

```text
durable state:
  A = Active
  C = Preparing

observed libvirt:
  persistent domain wskazuje zasoby C
```

Switch libvirt już się udał, pierwszy boot mógł być zdrowy, ale Forge nie zdążył wykonać finalnego transition indeksu. Taki stan nie może zostać uznany za `Consistent`. Sam fakt, że libvirt wskazuje C, nie dowodzi zakończenia cloud-init, poprawności użytkownika, SSH ani autoryzacji do promocji.

Prawidłowy wynik to:

```text
ManagedReconciliationStatus: RecoveryRequired
```

Forge nie wykonuje automatycznego rollbacku, ponieważ mógłby zniszczyć działającą, zdrową C. Nie wykonuje też auto-promocji, ponieważ obserwacja storage nie jest dowodem pełnego sukcesu guest OS. Zachowuje A i C, blokuje cleanup i wymaga jawnego recovery finalize.

## Observed generation

Observed generation nie jest rozpoznawana po nazwie pliku ani po tym, że volume „wygląda znajomo”. Nazwa jest pomocna dla operatora, ale nie stanowi identity.

Reconciliation wiąże generację z aktualnym libvirt state przez trwałe identyfikatory:

- domain UUID,
- storage pool UUID,
- dokładny `vda` volume key i path,
- dokładny seed volume key i path,
- backing relationship overlay → shared base.

Recovery używa jeszcze ostrzejszego exact match, obejmującego pełną tożsamość domeny, poola i wszystkich trzech ról zasobów. Brak dopasowania, wiele dopasowań albo observed generation różna od jedynej `Preparing` powodują odmowę.

## Problem z SSH agentem

W trakcie recovery GCR/GNOME SSH agent pokazywał klucz na liście, ale blokował operację podpisu. `ssh-add -l` potwierdzało obecność identity, natomiast `ssh-add -T` wisiało zamiast dowieść, że agent faktycznie potrafi użyć klucza.

Osobny OpenSSH `ssh-agent` rozwiązał problem. Dopiero poprawny test podpisu pozwolił przejść do ograniczonej czasowo próby SSH.

Wniosek:

```text
key listed != signing works
```

Lista identities opisuje zawartość agenta, ale nie gwarantuje dostępności operacji kryptograficznej. Test podpisu jest mocniejszym i właściwym preflightem.

## SSH host identity per generation

Generation C była nową instalacją i prawidłowo otrzymała nowy SSH host key. Pierwsza próba z `StrictHostKeyChecking=yes` została zablokowana, ponieważ klucz nie był jeszcze znany. To było poprawne zachowanie zabezpieczenia, a nie błąd do obejścia.

Publiczny klucz ED25519 został odczytany bez authentication, jego fingerprint SHA-256 został ręcznie zweryfikowany, a następnie dokładnie ten klucz zapisano w dedykowanym:

```text
~/.ssh/forge-recovery-known_hosts
```

Recovery używa:

- `BatchMode=yes`,
- finite timeout,
- `StrictHostKeyChecking=yes`,
- wyłącznie dedykowanego recovery known_hosts,
- wyłączonego globalnego known_hosts,
- dedykowanego klucza użytkownika `forge`.

Nie użyto `StrictHostKeyChecking=no`, globalnego TOFU ani automatycznego zaakceptowania nowego host key.

## Jawna finalizacja recovery

Komenda:

```text
forge state recover fedora-lab --dry-run
```

wykonała świeżą, read-only obserwowalność zamiast ufać logowi poprzedniego procesu. Warunki sukcesu obejmowały:

- domenę `running`,
- typed DHCP/IP discovery,
- obecny kanał QGA i poprawny `guest-ping`,
- SSH `Authenticated` przez zweryfikowany host identity,
- `CloudInitStatus: Done`,
- potwierdzenie użytkownika `forge`,
- hostname `fedora-lab`,
- dokładne identity domeny, poola, overlay, seeda, shared base i backing chain.

Realne:

```text
forge state recover fedora-lab
```

po jawnym potwierdzeniu wykonało wszystkie odczyty jeszcze raz. Zmiana indeksu, manifestów, libvirt identities, host identity lub observability pomiędzy planem i execute spowodowałaby odmowę.

Dopiero po drugiej rewalidacji wykonano jednym atomowym zapisem:

```text
A: Active    → Retained
C: Preparing → Active
active_generation_id = C
```

Immutable manifests nie zostały zmienione. B pozostała `Failed`.

## Finalny state

Po recovery:

```text
A = Retained
B = Failed
C = Active
active_generation_id = C
ManagedReconciliationStatus = Consistent
observed generation = C
```

Dokładnie jedna generacja jest `Active`, a observed libvirt generation jednoznacznie jej odpowiada.

## Cleanup dry-run

Po raz pierwszy Forge posiada prawdziwy cleanup candidate wynikający z pełnego lifecycle ownership:

- A jest `Retained Owned` i przeszła exact identity oraz reference checks,
- C jest `Active` i pozostaje chroniona,
- shared base jest `Shared / Protected`,
- volumes sprzed durable state nadal są `Unmanaged Legacy`,
- B jest `Failed` i nie podlega automatycznemu cleanupowi.

`forge vm cleanup fedora-lab --dry-run` nie mutuje state ani storage. Pokazuje kandydatów i dowody. Przyszły realny cleanup musi bezpośrednio przed każdym delete ponownie sprawdzić indeks, dokładną tożsamość volume, referencje ze wszystkich domain XML oraz backing references innych volumes.

Sama nieobecność volumes B nie zmienia jej automatycznie w `Cleaned` i nie daje prawa do porządkowania state heurystyką.

## Lekcje bezpieczeństwa

Prompt 11 utrwalił następujące reguły:

- brak automatycznego recovery,
- brak auto-promocji `Preparing`,
- brak rollbacku po niejednoznacznym lub już wykonanym switchu,
- brak cleanupu podczas `RecoveryRequired`,
- brak identyfikacji ownership po nazwach,
- brak auto-adoption legacy,
- brak delete dla `Active`, `Failed` i `Unmanaged`,
- `SharedBase` nigdy nie jest disposable candidate,
- brak `guest-exec`,
- brak `sudo`, Podmana i kodu `unsafe`,
- brak shellowego backendu `virsh`; operacje korzystają z typed libvirt API.

Fail closed oznacza tu zachowanie obu stron niejednoznacznego switchu i wymaganie jawnej decyzji, a nie próbę automatycznego „naprawienia” rzeczywistości.

## Najważniejsze komendy

```bash
forge vm rebuild fedora-lab --managed --dry-run
forge vm rebuild fedora-lab --managed
forge state reconcile fedora-lab
forge state recover fedora-lab --dry-run
forge state recover fedora-lab
forge vm cleanup fedora-lab --dry-run
ssh-add -T ~/.ssh/forge_ed25519.pub
```

## Co istnieje po Prompt 11

- multi-generation durable state,
- owned rebuild z Generation ID związanym z overlay i seedem,
- ownership zapisany przed switchem,
- crash-safe recovery boundary,
- explicit recovery finalize,
- retained owned generations,
- fail-closed cleanup eligibility,
- reconciliation aktualnej Active generation z libvirt.

## Czego nadal nie ma

- realnego cleanupu Retained A,
- adopcji legacy volumes,
- ogólnego SSH Host CA,
- Luny ani Codexa wewnątrz Fedora-Lab,
- profilu YOLO,
- GUI.

Prompt 11 kończy się na poprawnym stanie i bezpiecznie udowodnionym planie cleanupu. Nie usuwa jeszcze żadnego retained ani legacy storage.
