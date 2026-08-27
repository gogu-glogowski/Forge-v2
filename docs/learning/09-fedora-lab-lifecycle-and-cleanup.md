# Prompt 09: lifecycle Fedora-Lab i bezpieczne planowanie cleanupu

## Cel etapu

Prompt 09 domknął podstawowy lifecycle istniejącej Fedora-Lab. Forge potrafi teraz odczytać jej stan, bezpiecznie zaplanować start lub graceful shutdown oraz przygotować niewykonujący mutacji plan cleanupu starszej generacji storage.

Zakres obejmuje:

- `forge vm status fedora-lab`,
- `forge vm start fedora-lab`, także jako dry-run,
- `forge vm shutdown fedora-lab`, także jako dry-run,
- `forge vm cleanup fedora-lab --dry-run`.

Realny cleanup celowo nie powstał. Najpierw trzeba umieć jednoznacznie udowodnić własność zasobu, a nie tylko rozpoznać jego nazwę i kształt.

## Najważniejsza zasada ownership

```text
unreferenced + wygląda znajomo != proven ownership
```

Volume nie staje się bezpieczny do usunięcia tylko dlatego, że:

- ma nazwę znaną z wcześniejszego etapu,
- nie jest obecnie podpięty do Fedora-Lab,
- ma oczekiwany format i capacity,
- jego backing store wygląda poprawnie.

Taki zasób mógł zostać utworzony ręcznie, przejęty przez inną automatyzację albo zachowany świadomie. Brak aktywnej referencji dowodzi jedynie, że bieżące discovery tej referencji nie znalazło. Nie dowodzi, kto utworzył volume ani czy użytkownik zezwala Forge na jego usunięcie.

## Kategorie zasobów cleanupu

Plan rozróżnia cztery role:

- **active generation** — overlay i seed wskazywane przez persistent domain XML; muszą zostać zachowane,
- **retained generation** — starsze zasoby, które wyglądają jak poprzednia generacja, ale nie mają dostatecznego dowodu ownership,
- **shared base** — zaufany bazowy qcow2 używany jako backing; nie jest dyskiem instancji i zawsze pozostaje chroniony,
- **unknown/unmanaged resource** — zasób, którego pochodzenia lub roli Forge nie potrafi jednoznacznie ustalić.

Obecne legacy volumes mają poprawny shape i są unreferenced:

```text
fedora-lab.prepare.qcow2
fedora-lab-seed.iso
```

Discovery potwierdziło ich format, capacity, backing oraz brak referencji z persistent XML domen i backing chain innych znanych volumes. Mimo tego nie zostały cleanup candidates, ponieważ powstały przed wprowadzeniem trwałego metadata ownership. Są więc retained generation, nie zasobami przeznaczonymi do skasowania.

## Potrzebny generation manifest

Przyszłe generacje potrzebują minimalnego, atomowo zapisywanego manifestu, na przykład pod:

```text
~/.local/share/forge/state/
```

Manifest powinien rejestrować co najmniej identyfikator generacji i operacji, pool, volume identity, rolę zasobu, format, capacity oraz oczekiwany backing. Powinien powstawać razem z kontrolowanym lifecycle zasobu i nie może być rekonstruowany później z samej nazwy.

Manifest nie zastępuje libvirt jako source of truth. Przed cleanupem Forge nadal musi uzgodnić manifest z aktualnym stanem hypervisora:

- sprawdzić, czy volume istnieje w tym samym poolu,
- odczytać aktualny format, capacity i backing,
- przeskanować persistent XML wszystkich domen,
- sprawdzić backing chain wszystkich znanych volumes,
- odmówić cleanupu przy każdej rozbieżności lub niejednoznaczności.

## Druga ważna lekcja: domain topology != storage topology

Persistent domain XML i libvirt storage metadata opisują różne warstwy:

```text
domain XML
  → jaki volume jest podpięty jako vda
  → jaki seed jest podpięty jako CD-ROM
  → jakie kanały i urządzenia widzi domena

storage API
  → format qcow2 volume
  → virtual capacity
  → backing store overlay
  → relacje w storage chain
```

Domain XML mówi, że `fedora-lab.rebuild.qcow2` jest aktywnym `vda`. Nie musi jednak zawierać pełnej relacji backing store tego qcow2. Brak `<backingStore>` w domain XML nie oznacza, że overlay nie ma backing volume.

Wniosek jest prosty: topologię urządzeń domeny odczytujemy z domain XML, a topologię qcow2 z libvirt storage API.

## Failure mode: start odrzucony po poprawnym shutdownie

Pierwszy realny test lifecycle rozpoczął się poprawnie. Forge wysłał graceful shutdown i domena osiągnęła jednoznaczny stan `shutoff` przed upływem 120-sekundowego timeoutu. Nie użyto `destroy` ani force-off.

Następny start został jednak konserwatywnie odrzucony przez preflight. Discovery szukało backing store aktywnego overlay w persistent domain XML. Po wyłączeniu domeny XML nadal poprawnie wskazywał `vda`, ale nie raportował backing relationship. Forge zinterpretował to jako niemożność udowodnienia storage topology i nie wywołał libvirt `create`.

Było to bezpieczne zatrzymanie, ale błędne założenie o źródle danych.

Poprawka rozdzieliła odpowiedzialności:

1. Domain XML wskazuje ścieżkę aktywnego `vda`.
2. Forge odnajduje ten konkretny volume przez libvirt storage API.
3. Z jego metadata odczytuje format, capacity i backing path.
4. Osobno waliduje bazowy volume: istnieje, jest qcow2, ma oczekiwaną capacity i sam nie ma backing store.
5. Dopiero wtedy preflight startu uznaje storage chain za potwierdzony.

Dodany test regresyjny obejmuje persistent domenę w stanie `shutoff`, której domain XML zawiera tylko ścieżkę `vda`, podczas gdy prawidłowy backing pochodzi ze storage metadata.

## Finalny lifecycle

### Status

Status łączy dane z kilku źródeł bez mutacji:

- stan, UUID i persistent flag domeny,
- aktywny overlay i seed,
- backing chain oraz parametry volumes,
- aktywność sieci `default`,
- obecność kanału QGA,
- QGA i adresy IP, gdy domena działa.

### Start

Start wykonuje pełny preflight i ponowną walidację bezpośrednio przed mutacją. Dla domeny już działającej zwraca typed `AlreadyRunning` bez drugiego `create`. Dla poprawnej domeny `shutoff` wywołuje start dokładnie raz, czeka na `Running`, a następnie uruchamia istniejącą typed observability.

### Shutdown

Shutdown używa wyłącznie graceful libvirt shutdown i czeka maksymalnie 120 sekund na `shutoff`. Domena już wyłączona daje typed `AlreadyShutoff`. Nie istnieje automatyczny fallback do `destroy` lub force-off.

### Observability po starcie

```text
DomainBootStatus
  → DHCP/IP
  → QGA guest-ping
  → SSH jako forge
  → CloudInitStatus
  → potwierdzenie użytkownika i hostname
```

QGA służy do standardowej telemetrii, nie do `guest-exec`. Stan cloud-init, użytkownik i hostname są potwierdzane przez SSH jako `forge`, bez sudo i root SSH. Każdy etap ma jawny, skończony timeout.

## Finalny potwierdzony rezultat

Kontrolowany test end-to-end potwierdził:

```text
graceful shutdown:       Success
start:                   Success, dokładnie jedno libvirt create
DomainBootStatus:        Running
DHCP:                    Available
GuestAgentStatus:        Available
SshStatus:               Authenticated
CloudInitStatus:         Done
forge_user_confirmed:    true
user:                    forge
hostname:                fedora-lab
```

Po starcie aktywne `vda`, backing base i seed pozostały te same. Wzrost allocation zapisywalnego overlay jest normalnym skutkiem pracy guest OS, a nie zmianą topologii storage.

## Cleanup dry-run

Dry-run chroni:

- aktywny `fedora-lab.rebuild.qcow2`,
- aktywny seed NoCloud,
- współdzielony Fedora base volume,
- persistent definicję i UUID domeny.

Obecny plan ma zero realnych delete candidates. Starszy overlay i seed pozostają retained, ponieważ ich ownership nie jest potwierdzony trwałym metadata. W Prompt 09 nie powstała żadna ścieżka CLI wykonująca delete.

## Wnioski security

- Shutdown jest graceful; brak `destroy` i force-off.
- Start jest poprzedzony preflightem i wykonuje `create` najwyżej raz.
- `AlreadyRunning` oraz `AlreadyShutoff` są jawnie idempotentne.
- Nie ma realnego cleanupu ani heurystycznego kasowania po nazwach.
- Nie ma `guest-exec`, sudo ani root SSH.
- Nie użyto Podmana ani `unsafe`.
- Niepewność dotycząca ownership lub storage topology kończy się odmową, nie próbą zgadywania.

## Najważniejsze komendy

Lifecycle i status:

```bash
forge vm status fedora-lab
forge vm start fedora-lab
forge vm start fedora-lab --dry-run
forge vm shutdown fedora-lab
forge vm shutdown fedora-lab --dry-run
forge vm cleanup fedora-lab --dry-run
```

Walidacja kodu:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

## Co istnieje po Prompt 09

- read-only, wieloźródłowy status Fedora-Lab,
- bezpieczny i idempotentny start,
- graceful shutdown z timeoutem i bez force-off,
- typed observability po starcie,
- konserwatywny cleanup dry-run,
- skan referencji domen i backing chain volumes,
- regresja chroniąca poprawne rozdzielenie domain XML od storage metadata.

## Czego nadal nie ma

- realnego cleanupu i usuwania generations,
- generation manifestu z durable ownership metadata,
- Luny ani Codexa,
- profilu YOLO,
- własnego GUI,
- funkcji z kolejnego etapu projektu.
