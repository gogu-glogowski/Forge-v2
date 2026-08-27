# Prompt 10: trwały state i ownership generacji

## Cel etapu

Prompt 10 dodał trwałą pamięć o zasobach utworzonych i zarządzanych przez Forge. Samo discovery libvirt mówi, co istnieje teraz, ale nie odpowiada na pytanie, czy Forge ma prawo uznać konkretny zasób za własny. Do tego potrzebny jest zapis historycznej intencji.

Etap objął:

- versioned generation manifest dla Fedora-Lab,
- trwałą generation identity,
- atomowy state store użytkownika,
- read-only discovery aktualnego stanu libvirt,
- typed reconciliation manifestu z hypervisorem,
- bezpieczną adopcję aktywnej generacji powstałej przed durable state.

## Najważniejsza zasada

```text
Forge state != hypervisor source of truth
```

Każda warstwa odpowiada na inne pytanie:

- **Forge manifest** mówi, które zasoby Forge uważa za swoje i do jakiej generacji oraz roli je przypisał.
- **Domain XML** mówi, które urządzenia są obecnie podpięte do domeny, między innymi aktywny `vda` i NoCloud seed.
- **Libvirt storage API** mówi, jaki jest rzeczywisty pool, volume identity, format, capacity oraz backing chain.

Dopiero zgodność wszystkich trzech warstw daje wynik:

```text
ReconciliationStatus: Consistent
```

Manifest nie może przesłonić aktualnego stanu hypervisora. Libvirt nie potrafi natomiast sam udowodnić historycznej intencji Forge.

## Dlaczego potrzebowaliśmy manifestu

Po Prompt 09 istniały dwa starsze volumes:

```text
fedora-lab.prepare.qcow2
fedora-lab-seed.iso
```

Były unreferenced, a ich format, capacity i backing wyglądały jak zasoby wcześniejszej generacji Forge. To nadal nie stanowiło dowodu ownership.

Nazwa może zostać użyta ręcznie. Poprawny shape mówi tylko, jak zasób wygląda obecnie. Brak referencji mówi tylko, że aktualne discovery nie znalazło konsumenta. Żaden z tych faktów nie dowodzi, kto utworzył zasób ani czy wolno go usunąć.

Prompt 10 rozwiązuje ten problem dla przyszłych decyzji. Ownership pochodzi z manifestu zapisanego podczas jawnego lifecycle, a następnie jest każdorazowo weryfikowany przez reconciliation.

## Architektura

Powstał osobny crate `forge-state`.

Jego odpowiedzialność obejmuje:

- typed modele manifestu i obserwowanego stanu,
- JSON serialization i fail-closed parsing,
- atomowy zapis i odczyt plików,
- planowanie adopcji,
- czystą logikę reconciliation.

`forge-state` nie zależy od libvirt. Dzięki temu reconciliation można testować bez hypervisora, a sam crate nie ma możliwości mutowania domeny lub storage.

`forge-libvirt` pozostaje adapterem. W Prompt 10 udostępnia wyłącznie read-only discovery:

- tożsamości domeny,
- persistent domain XML i aktywnych urządzeń,
- URI połączenia,
- UUID poola,
- volume keys, paths, formatów, capacity i backing chain.

CLI koordynuje odczyt manifestu, discovery i czyste reconciliation.

## Generation manifest

Manifest używa jawnie wersjonowanego JSON. JSON został wybrany zamiast własnego formatu, ponieważ jest czytelny, łatwy do inspekcji i obsługiwany przez `serde` bez budowania parsera.

Najważniejsze pola:

```json
{
  "schema_version": 1,
  "domain_name": "fedora-lab",
  "domain_uuid": "<libvirt-domain-uuid>",
  "generation_id": "gen-<uuid-v4>",
  "created_unix_seconds": 0,
  "libvirt_uri": "qemu:///system",
  "storage_pool_name": "default",
  "storage_pool_uuid": "<libvirt-pool-uuid>",
  "status": "active",
  "resources": []
}
```

Każdy managed resource zapisuje:

- typed role,
- volume name,
- volume key zwrócony przez libvirt,
- path zwrócony przez libvirt,
- format,
- virtual capacity,
- backing path, jeżeli istnieje.

Manifest nie przechowuje kluczy SSH, haseł, tokenów, zawartości seeda ani innych sekretów.

## Generation ID

Generation ID jest losowym UUID v4 generowanym z systemowego kryptograficznie bezpiecznego RNG. Ma zapewnić unikalną i stabilną tożsamość generacji po zapisaniu manifestu.

Pierwsza wersja projektu ID używała SHA-256 złożonego między innymi z domain UUID, pool UUID, volume keys, timestampu i PID. To było błędne modelowanie. Taki hash nie dawał dodatkowego dowodu ownership, a mógł sugerować, że właściwości samego ID zapewniają bezpieczeństwo.

Refinement usunął hash, PID, timestamp i nazwy zasobów z generowania ID. Obecnie:

```text
Generation ID = losowy UUID v4
Ownership = durable manifest + reconciliation z libvirt
```

Dry-run pokazuje jedynie planned generation ID. Przy realnej adopcji jeden UUID zostaje wygenerowany, zamrożony w planie i zapisany bez zmiany. `show`, ponowny odczyt i `reconcile` nie generują nowego ID.

## Typed role zasobów

Manifest używa trzech jawnych ról:

- `SharedBase` — zaufany bazowy qcow2,
- `WritableOverlay` — zapisywalny dysk konkretnej generacji,
- `NoCloudSeed` — seed provisioningowy konkretnej generacji.

`SharedBase` jest zasobem Forge, ale nie jest disposable generation resource. Może być współdzielony przez wiele generacji i overlayów. Sam fakt, że jedna generacja przestaje go używać, nie może kwalifikować base do cleanupu.

Overlay i seed są związane z konkretną generacją oraz domeną. Ich manifestowana tożsamość nadal musi zgadzać się z aktywnymi referencjami domain XML i aktualnym storage API.

## Atomowy zapis state

State użytkownika znajduje się pod:

```text
~/.local/share/forge/state/
```

Manifest nie jest zapisywany bezpośrednio do finalnego pliku. Lifecycle zapisu wygląda następująco:

```text
serialize
  → temporary file w tym samym katalogu
  → write
  → flush
  → fsync pliku
  → atomic rename
  → fsync katalogu
```

Temporary file od początku ma prywatne permissiony. Forge jawnie wymusza:

```text
state directory: 0700
manifest file:   0600
```

Nie polega więc wyłącznie na `umask`. Test awarii temporary write potwierdza, że poprzedni poprawny manifest pozostaje nienaruszony.

## Fail-closed parsing

Parser używa `serde` i odrzuca nieznane pola manifestu. Błędy są typed:

- nieobsługiwana wersja schematu → `UnsupportedSchema`,
- uszkodzony JSON → `CorruptManifest`,
- brak wymaganych pól → `CorruptManifest`,
- brak manifestu → `Missing`, nie błąd libvirt,
- niezgodność domeny, poola lub storage → reconciliation failure.

Forge nie próbuje poprawiać manifestu na podstawie nazw ani aktualnego kształtu zasobów. Konflikt jest raportowany i wymaga jawnej decyzji w późniejszym lifecycle.

## Typed reconciliation

Wynik nie jest zwykłym `true` albo `false`:

- `Consistent` — manifest i aktualny stan są zgodne,
- `Drifted` — zmieniły się parametry, na przykład format lub capacity,
- `Missing` — manifestowany zasób nie istnieje,
- `Conflict` — nie zgadza się tożsamość lub relacja, na przykład UUID, volume key, path albo backing,
- `Unmanaged` — zasób istnieje, ale nie ma dowodu ownership Forge,
- `CorruptState` — manifestu nie można bezpiecznie sparsować.

Raport zawiera konkretne pole, wartość oczekiwaną i wartość zaobserwowaną. Przykładowo manifestowane:

```text
overlay A → base B
```

oraz zaobserwowane:

```text
overlay A → base C
```

dają konflikt. Forge nie aktualizuje wtedy manifestu automatycznie.

## Adopcja istniejącej Fedora-Lab

Fedora-Lab powstała przed durable state. Nie można więc było uznać wszystkich historycznych volumes za owned.

Adopcja zastosowała sekwencję:

```text
discover
  → prove active topology
  → show adoption plan
  → explicit confirmation
  → repeat read-only discovery
  → reconcile frozen plan with fresh state
  → atomic local manifest write
  → read manifest again
  → reconcile with libvirt
```

Jednoznacznie adoptowano tylko aktywne zasoby:

- shared Fedora base,
- aktywny writable overlay,
- aktywny NoCloud seed.

Starszy overlay i seed pozostały `Unmanaged`. Brak historycznego dowodu nie został „naprawiony” przez heurystykę.

Realna adopcja zmieniła wyłącznie lokalny state Forge. Porównanie domeny, poola i listy volumes przed i po operacji potwierdziło brak mutacji libvirt.

## Finalny rezultat

```text
generation ID: gen-18e65c1d-13fd-4b4f-b689-7f6b0ca08a39
manifest:      ~/.local/share/forge/state/fedora-lab.json
reconciliation: Consistent
state dir mode: 0700
manifest mode:  0600
```

Generation ID pozostaje taki sam przy `show`, ponownym odczycie i reconciliation.

## Najważniejsze wnioski security

- Manifest nie jest „bogiem prawdy”. Jest trwałym dowodem deklaracji ownership Forge.
- Aktualny stan domeny i storage zawsze pochodzi z libvirt.
- Reconciliation jest wymagane przed przyszłymi operacjami destrukcyjnymi.
- Nazwa, shape i brak referencji nie zastępują durable ownership.
- Shared base nie może być traktowany jak disposable disk pojedynczej generacji.
- Manifest nie zawiera sekretów ani materiału SSH.
- Prompt 10 nie używa sudo i nie zmienia permissionów libvirt volumes.
- Libvirt pozostaje read-only: brak startu, shutdownu, redefine, tworzenia lub usuwania volumes.
- Nie użyto Podmana, `virsh` jako backendu, QGA `guest-exec` ani `unsafe`.

## Najważniejsze komendy

```bash
forge state show fedora-lab
forge state reconcile fedora-lab
forge state adopt fedora-lab --dry-run
forge state adopt fedora-lab
```

Walidacja kodu:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

## Co istnieje po Prompt 10

- durable ownership aktywnej generacji Fedora-Lab,
- stabilna generation identity oparta na UUID v4,
- versioned i prywatny state store użytkownika,
- atomowy zapis odporny na częściową awarię,
- typed resource roles,
- read-only discovery domeny i storage,
- typed reconciliation manifestu z libvirt,
- jawne rozróżnienie managed active generation i unmanaged legacy resources.

## Czego nadal nie ma

- realnego cleanupu owned generations,
- automatycznej migracji wersji schematu state,
- Luny ani Codexa,
- profilu YOLO,
- własnego GUI,
- funkcji Prompt 11.
