# ÁBACO

**Benchmark suite for the ÁGORA verifiable-voting core:** homomorphic ElGamal, Schnorr/Chaum-Pedersen ZKPs, Merkle transparency logs, and threshold decryption — measured at real election scale.

> **English (short version).** ÁBACO measures the *computational cost* of the cryptography behind verifiable electronic voting: exponential ElGamal encryption, zero-knowledge ballot-validity proofs, an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle transparency log, and Shamir threshold decryption — from 1,000 up to 10,000,000 votes, with a per-operation breakdown, statistical rigor, and reproducible, citable output. It is **not** a voting system; it is a measurement instrument. It exists to replace an unsupported claim ("the cost of verifiable cryptography is negligible") with a measured, reproducible number. Full documentation below is in Spanish, the language of its primary audience (an academic tribunal in Uruguay). Jump to [Quickstart](#quickstart), [the cryptographic spec](#especificación-criptográfica), or [Non-goals](#no-objetivos-y-limitaciones).

---

## Qué es y por qué existe

**ÁGORA** es un sistema de votación electrónica auditable; **FARO** es su log público append-only. Son los dos productos de un Proyecto Final de Grado de Ingeniería en Informática de la **Universidad Católica del Uruguay (UCU)**.

La arquitectura de ÁGORA descansa sobre criptografía verificable:

- Cifrado homomórfico **ElGamal exponencial** — permite sumar votos cifrados sin descifrarlos; solo se descifra el total.
- **Pruebas de conocimiento cero** (Chaum-Pedersen + composición OR estilo CDS, Fiat-Shamir) — prueban que un voto es válido sin revelar su contenido.
- Log **Merkle append-only** ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), el formato de Certificate Transparency que usa [Tessera](https://github.com/transparency-dev/tessera)).
- **Descifrado por umbral** con Shamir secret sharing — ninguna autoridad tiene la clave completa.

Una afirmación central del proyecto es que **el costo computacional de esa criptografía verificable es despreciable**. Hasta ahora era una estimación sin respaldo. **ÁBACO existe para convertirla en un dato medido, reproducible y citable.** Por eso el diseño prioriza tres cosas:

1. **Rigor metodológico** — warmup, repeticiones, mediana/p95/p99, distinción explícita entre *wall-clock* y *CPU time*, y medición del propio overhead del instrumento.
2. **Reproducibilidad y citabilidad** — cada corrida registra hardware, versión de Go, commit, semilla y parámetros. El JSON de salida es autosuficiente.
3. **Corrección verificable** — al final de cada escala, el conteo descifrado se compara con el esperado; si no coincide, la corrida falla ruidosamente. Un benchmark de una operación incorrecta no vale nada.

El nombre sigue la familia del proyecto: ÁGORA (la plaza) → FARO (el faro) → **ÁBACO** (el instrumento de contar).

## Qué mide

El pipeline criptográfico completo de una elección, operación por operación:

| # | Operación | Paquete |
|---|---|---|
| 1 | Cifrar un voto (ElGamal exponencial) | `internal/elgamal` |
| 2 | Generar la ZKP de validez `{0,1}` (OR-proof) | `internal/zkp` |
| 3 | Verificar la ZKP `{0,1}` | `internal/zkp` |
| 4 | Generar la prueba de papeleta 1-de-C | `internal/zkp` |
| 5 | Verificar la prueba 1-de-C | `internal/zkp` |
| 6 | Sumar votos (agregación homomórfica) | `internal/elgamal` |
| 7 | Insertar en el Merkle (RFC 6962) | `internal/merkle` |
| 8 | Descifrado parcial por autoridad | `internal/threshold` |
| 9 | Combinación de Lagrange | `internal/threshold` |
| 10 | BSGS: recuperar el conteo | `internal/bench` |

Y, fuera del camino caliente, las dos pruebas de auditoría de FARO — **inclusion proof** y **consistency proof** (generación y verificación, más el tamaño de la prueba) — medidas en escalas propias vía `--proof-votes` (`internal/merkle`).

## Quickstart

Requiere **Go 1.23+**.

```console
$ git clone https://github.com/felicabrera/abaco && cd abaco
$ go build -o abaco .

# Recorrido pedagógico de un solo voto, paso a paso:
$ ./abaco demo --seed 42

# El benchmark principal:
$ ./abaco bench --votes 1000,10000,100000 --repeat 3 --seed 42

# Con las pruebas de auditoría (inclusion + consistency) en escalas propias:
$ ./abaco bench --votes 1000,10000,100000 \
    --proof-votes 1000,100000,1000000 --proof-samples 256 --seed 42

# El entorno detectado (para pegar en un informe):
$ ./abaco env
```

O con `make`: `make demo`, `make bench`, `make test`.

## Ejemplo de salida real

Corrida verdadera en un **Apple M5 Pro** (18 cores), Go 1.26.5, `--votes 1000,10000,100000 --repeat 3 --seed 42`:

```
Environment
  CPU: Apple M5 Pro | Cores used: 18 of 18
  RAM: 48.0 GiB | GOMEMLIMIT: none | Peak heap: 8.9 MiB
  Go: go1.26.5 | OS/Arch: darwin/arm64 | Group: ristretto255
  Commit: f44f753450f7-dirty | Seed: 42 | Date: 2026-07-18T02:35:52Z
  Instrument overhead (time.Now pair): 78 ns

Table 1 — Summary per scale
Votes    Wall (median)  CPU work   Ballots/s  Ciphertexts/s  Peak heap  Correct
1,000    171.41 ms      2.891 s    5,833      11,667         4.6 MiB    yes
10,000   1.726 s        29.216 s   5,794      11,588         6.4 MiB    yes
100,000  17.126 s       288.658 s  5,839      11,678         8.9 MiB    yes

Table 2 — Operation breakdown @ 100,000 votes (2 candidates)
Operation            Calls    Median     Mean       p95        Total CPU  % pipeline
Encrypt              600,000  95.04 µs   138.19 µs  101.92 µs  82.914 s   9.5%
Prove ballot {0,1}   600,000  335.54 µs  458.24 µs  598.05 µs  274.943 s  31.5%
Verify ballot {0,1}  600,000  454.38 µs  622.33 µs  858.30 µs  373.396 s  42.8%
Prove 1-of-C         300,000  110.38 µs  154.44 µs  119.55 µs  46.333 s   5.3%
Verify 1-of-C        300,000  228.33 µs  313.07 µs  292.73 µs  93.920 s   10.8%
Homomorphic add      600,000  708 ns     794 ns     1.17 µs    476.17 ms  0.1%
Merkle append        300,000  333 ns     390 ns     792 ns     116.90 ms  0.0%
Partial decrypt      18       56.62 µs   56.82 µs   57.51 µs   1.02 ms    0.0%
Lagrange combine     6        204.27 µs  204.06 µs  207.68 µs  1.22 ms    0.0%
BSGS recover tally   6        3.73 ms    3.73 ms    3.75 ms    22.38 ms   0.0%
```

Y las pruebas de auditoría (`--proof-votes 1000,100000,1000000 --proof-samples 128`), medidas aparte porque no están en el camino caliente:

```
Table 2 — Audit proofs @ 1,000 entries
Operation           Calls  Median   Mean     p95      Total CPU
Inclusion prove     128    917 ns   969 ns   1.62 µs  124.05 µs
Inclusion verify    128    1.46 µs  1.48 µs  1.54 µs  189.00 µs
Consistency prove   128    917 ns   1.04 µs  1.69 µs  132.79 µs
Consistency verify  128    1.92 µs  1.92 µs  2.44 µs  246.16 µs
  Inclusion proof:   10 hashes / 320 B   (log2 n = 10.0)
  Consistency proof: 11 hashes / 352 B (4–11 across samples)   (log2 n = 10.0)

Table 2 — Audit proofs @ 1,000,000 entries
Operation           Calls  Median   Mean     p95      Total CPU
Inclusion prove     128    1.38 µs  1.50 µs  1.90 µs  191.93 µs
Inclusion verify    128    2.33 µs  2.52 µs  3.93 µs  322.38 µs
Consistency prove   128    1.08 µs  1.32 µs  3.78 µs  169.45 µs
Consistency verify  128    2.94 µs  2.95 µs  3.46 µs  378.08 µs
  Inclusion proof:   20 hashes / 640 B   (log2 n = 20.0)
  Consistency proof: 21 hashes / 672 B (16–21 across samples)   (log2 n = 20.0)
```

El log crece 1.000×, pero la prueba de inclusión pasa de 10 a 20 hashes (320 → 640 B) y la verificación de ~1,5 a ~2,3 µs: **`O(log n)`, no `O(n)`.** Ese es el argumento de FARO — auditar es barato para cualquiera, en hardware común.

### Cómo leer estos números

- **La memoria es plana.** El pico de heap pasa de 4.6 a 8.9 MiB mientras los votos van de 1.000 a 100.000 — dos órdenes de magnitud más votos, memoria casi constante. Es el resultado más valioso del proyecto (ver [Arquitectura](#arquitectura-por-qué-la-memoria-es-plana)).
- **Wall ≠ CPU.** A 100k votos, el *wall time* es 17,1 s pero el trabajo agregado de CPU es 288,7 s: ~17× de aceleración por los 18 cores. Confundir ambos números es un error que un tribunal puede detectar; por eso se reportan por separado.
- **Dónde está el costo.** Cifrar es el ~9,5 % del pipeline criptográfico; las **pruebas verificables** (generar+verificar la ZKP `{0,1}` y la 1-de-C) son ~90 %. Insertar en el Merkle y sumar homomórficamente son <0,2 %. Es decir: el diferencial de ÁGORA (la verificabilidad) es lo que domina *dentro* del núcleo cripto — pero en términos absolutos son ~1–2 ms de cómputo por papeleta, despreciable frente a la red, la base de datos y el renderizado de UI de una elección real. ÁBACO mide el núcleo; no infla ni oculta ese matiz.

El JSON completo (`--json results.json`) trae, por escala, todas las estadísticas por operación, el entorno y los parámetros, listo para citar.

## Especificación criptográfica

Todo esto es criptografía estándar y documentada; ÁBACO no inventa variantes. Las referencias están citadas en los comentarios del código.

**Grupo.** [ristretto255](https://ristretto.group/) (RFC 9496) sobre Curve25519: grupo de **orden primo**, sin cofactor ni subgrupos pequeños — justo lo que ElGamal y Schnorr asumen. Está detrás de una interfaz (`internal/group`) para poder añadir un backend P-256 y comparar; ese backend debería documentar que usa las APIs de `crypto/elliptic` deprecadas desde Go 1.21.

**ElGamal exponencial.** Clave privada `x`, pública `Y = xG`. Cifrado de `m` con aleatoriedad fresca `r`: `A = rG`, `B = rY + mG`. Homomórfico: `(A₁+A₂, B₁+B₂)` cifra `m₁+m₂`. Descifrado: `mG = B − xA`, y luego se resuelve un log discreto acotado. La frescura de `r` da seguridad semántica (IND-CPA) — lo que permite que FARO sea público. *(ElGamal 1985; Cramer-Gennaro-Schoenmakers, EUROCRYPT '97.)*

**ZKP de validez `{0,1}` (OR-proof).** Prueba disyuntiva de que el ciphertext cifra 0 **o** 1, sin revelar cuál: composición OR estilo CDS de dos sigma-protocolos Chaum-Pedersen de igualdad de logaritmos discretos, hecha no interactiva con Fiat-Shamir. El hash incluye un **domain separator** (`ABACO/v1/ballot-proof`), la clave pública `Y` y el ciphertext completo — omitirlos rompe la solidez. *(Cramer-Damgård-Schoenmakers, CRYPTO '94; Chaum-Pedersen, CRYPTO '92; Fiat-Shamir, CRYPTO '86.)*

**Prueba de papeleta 1-de-C.** La OR-proof por ciphertext solo garantiza `{0,1}` en cada casilla; para la fidelidad a un voto real hace falta probar que la papeleta cifra **exactamente un 1**. ÁBACO añade una prueba Chaum-Pedersen sobre el ciphertext agregado `(ΣAᵢ, ΣBᵢ)` de que cifra 1 (dominio `ABACO/v1/sum-proof`). Una papeleta que vota a dos candidatos es rechazada.

**Descifrado por umbral (Shamir).** Polinomio de grado `t−1` sobre `Z_q` con `x = f(0)`; shares `(i, f(i))`. Cada autoridad publica `Dᵢ = xᵢ·A`; la combinación de Lagrange en 0 recupera `x·A`, y `mG = B − xA`. Con `t−1` shares no se puede; con `t`, sí. *(Shamir, CACM 1979; Pedersen, EUROCRYPT '91.)*

**Recuperación del conteo (BSGS).** El total está en `[0, N]`; baby-step/giant-step lo recupera en `O(√N)`. Para 10M votos, ~3.163 entradas. Se mide por separado del descifrado parcial.

**Merkle (RFC 6962).** `leaf = SHA-256(0x00 ‖ entry)`, `node = SHA-256(0x01 ‖ left ‖ right)`. Los prefijos de dominio previenen ataques de segunda preimagen. El árbol es **incremental/streaming** (una pila de raíces de subárboles, memoria `O(log n)`). Además se **miden** las dos pruebas que hacen auditable al log — la funcionalidad central de FARO:

- **Inclusion proof** (audit path): prueba que una papeleta cifrada está en el log con raíz `R`, sin revelar el resto. Son ~log₂(n) hashes hermanos; el verificador recomputa la raíz. Es lo que permite a un votante confirmar "mi voto quedó registrado".
- **Consistency proof**: prueba que el log es *append-only* — que un árbol anterior (tamaño `m`) es prefijo de uno posterior (tamaño `n`), sin reordenar, editar ni borrar. Es lo que permite a un auditor confirmar "el log no fue manipulado".

Ambas se generan desde un árbol almacenado en `O(log n)` (como lo haría un servidor de log real; validado por igualdad byte a byte contra la implementación de referencia `O(n)` y contra los vectores conocidos de Certificate Transparency). El resultado clave es que **el tamaño de la prueba y el costo de verificación crecen con `log n`, no con `n`**: auditar un log de un millón de entradas cuesta el mismo puñado de hashes que uno de mil. Se miden con `--proof-votes` (escalas independientes de `--votes`, para no romper la memoria plana del pipeline) y `--proof-samples`.

## Arquitectura: por qué la memoria es plana

Para que 10M de votos entren en poca RAM, **no se retienen todos los votos en memoria**. El pipeline es:

```
por cada lote de tamaño --batch:
  EN PARALELO (worker pool = --cores): por papeleta
      cifrar · probar {0,1} · verificar {0,1}  (por cada candidato)
      probar 1-de-C · verificar 1-de-C
  SECUENCIAL, en orden de índice (el Merkle exige orden determinista):
      sumar homomórficamente al acumulador · insertar en el Merkle · descartar la papeleta
al final:
  descifrado parcial · combinación Lagrange · BSGS · VERIFICAR conteo == esperado
```

El pico de memoria es `O(batch × C + log n + √N)`: **constante respecto a la cantidad de votos**. La aleatoriedad se deriva de forma determinista del índice de papeleta (`H(seed ‖ i)`), así que el resultado es idéntico sin importar cuántos cores se usen — verificado en los tests.

## Metodología de medición

- **Warmup** (default 100) antes de medir, para no contaminar con page faults ni branch-predictor frío.
- **Repeticiones** (`--repeat`): la mediana es la métrica principal (resiste outliers); se reportan también media, p95, p99, min, max y desvío.
- Percentiles por operación vía **muestreo de reservorio** (Algoritmo R, 8192 muestras/op): estadística estable con memoria acotada incluso a 10M de votos. Count, total, media y desvío son exactos.
- **Wall-clock vs CPU time** distinguidos explícitamente.
- **Overhead del instrumento** (`time.Now()` ≈ 78 ns aquí) medido y reportado.
- **Semilla siempre reportada**, aunque sea aleatoria.

## Reproducir una corrida exacta

El JSON de salida contiene todo lo necesario. Para repetir bit a bit la corrida de arriba:

```console
$ ./abaco bench --votes 1000,10000,100000 --candidates 2 \
    --authorities 5 --threshold 3 --repeat 3 --seed 42 --json results.json
```

Misma semilla ⇒ misma distribución de votos, mismos ciphertexts y mismo conteo verificado, en cualquier hardware. Los *tiempos* dependen de la máquina (ver [No-objetivos](#no-objetivos-y-limitaciones)); el `Environment` block y el JSON registran en cuál se corrió.

## Seguimiento continuo (CI)

Cada push a `main` dispara el workflow [`.github/workflows/benchmark.yml`](.github/workflows/benchmark.yml), que corre el pipeline (`--proof-votes none`) y las pruebas de auditoría como dos invocaciones separadas, con **la misma semilla (42) y las mismas escalas (1k/10k/100k/1M)** en cada commit. Así los números del informe dejan de ser una foto puntual y pasan a ser una serie temporal comparable.

Cada corrida: sube `pipeline.json` y `proofs.json` como artefactos (identificados por SHA), imprime las tablas legibles al log del job, y publica en el *job summary* un diff commit-a-commit de las medianas clave —Encrypt, Prove/Verify ballot y verify/tamaño de las pruebas de auditoría— contra el commit anterior de `main`. Un movimiento mayor a ±10% se marca con ⚠️, pero **no** rompe el build por defecto (el ruido de rendimiento no debe bloquear merges); fallar ante una regresión es opt-in vía la entrada `fail_on_regression` del `workflow_dispatch`. El diff se genera con `abaco benchdiff --old <base>.json --new <actual>.json`, y el baseline vive en la rama `bench-baseline`. Atajo local: `make bench-ci`.

> El runner es de GitHub (compartido), así que los *números absolutos* son ruidosos; solo son confiables los deltas relativos grandes. Para cifras absolutas citables, correr en hardware fijo (ver [Metodología](#metodología-de-medición)).

## Límites de recursos duros (Docker)

`--mem` usa `debug.SetMemoryLimit` (GOMEMLIMIT), que es un límite **blando**: presiona al GC, no es un cap duro. Para una simulación defendible de una máquina de 1 GB / 2 cores hay que correr bajo cgroups:

```console
$ docker build -t abaco .
$ docker run --rm --memory=1g --cpus=2 abaco \
    bench --votes 1000000 --cores 2 --mem 1GiB --repeat 1 --seed 42
```

Dentro de ese contenedor, superar 1 GB es un OOM kill, no un simple enlentecimiento — por eso una corrida que completa demuestra de verdad la memoria plana. Atajo: `make docker-bench`.

## No-objetivos y limitaciones

Declararlos protege la honestidad intelectual del proyecto:

- **ÁBACO no es un sistema de votación.** No maneja votantes, padrones ni autenticación. Es un instrumento de medición.
- **La implementación criptográfica es de referencia, no de producción.** No fue auditada por terceros ni endurecida contra ataques de canal lateral (timing, cache). Sirve para medir el orden de magnitud del costo, no para desplegar.
- **No mide la infraestructura completa.** Nada de red, base de datos ni UI. Solo el núcleo criptográfico.
- **Los resultados dependen del hardware.** Un número medido en un M5 Pro no aplica a un servidor de €57/mes sin volver a correrlo ahí.
- **Descifrado con dealer confiable.** El reparto de shares usa un dealer (Shamir). Una variante sin dealer (Pedersen '91) no cambiaría los tiempos por operación medidos.

## Estructura del repositorio

```
main.go, cmd_*.go        # CLI: demo, bench, env (flag stdlib)
internal/group/          # interfaz del grupo + backend ristretto255
internal/elgamal/        # ElGamal exponencial
internal/zkp/            # OR-proof {0,1} + prueba 1-de-C (Chaum-Pedersen + Fiat-Shamir)
internal/threshold/      # Shamir + descifrado por umbral
internal/merkle/         # RFC 6962 incremental + inclusion/consistency proofs
internal/bench/          # BSGS, pipeline streaming, timers, memoria, límites
internal/report/         # tablas (tabwriter), JSON (schema_version:1), CSV
```

## Tests

```console
$ go test ./...        # corrección cripto, e2e, determinismo
$ go vet ./... && staticcheck ./...
```

Incluye, entre otros: `Decrypt(Encrypt(m))==m`, homomorfismo, IND-CPA, **la ZKP de un voto inválido (m=2) es rechazada**, prueba manipulada rechazada, **la papeleta que vota a dos candidatos es rechazada**, umbral (`t` descifra, `t−1` no), Merkle contra el vector de prueba de RFC 6962, inclusion/consistency proofs, elección end-to-end de 1.000 votos con conteo exacto, y determinismo idéntico entre 1 y 8 cores.

## Cómo citarlo

Ver [`CITATION.cff`](CITATION.cff). Autor: Felipe Cabrera (Universidad Católica del Uruguay).

## Licencia

Apache 2.0 — ver [`LICENSE`](LICENSE).

## Referencias

**Criptografía.** ElGamal (1985) · Cramer, Damgård, Schoenmakers, *Proofs of Partial Knowledge*, CRYPTO '94 · Cramer, Gennaro, Schoenmakers, *A Secure and Optimally Efficient Multi-Authority Election Scheme*, EUROCRYPT '97 · Chaum, Pedersen, CRYPTO '92 · Fiat, Shamir, CRYPTO '86 · Schnorr (1991) · Shamir, *How to Share a Secret*, CACM 1979 · Pedersen, EUROCRYPT '91 · Bünz et al., *Bulletproofs*, IEEE S&P 2018 (contexto).

**Estándares y sistemas.** [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Certificate Transparency) · [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) · [Tessera](https://github.com/transparency-dev/tessera) · [ristretto255 / RFC 9496](https://ristretto.group/) · [Helios](https://heliosvoting.org/) · [Belenios](https://www.belenios.org/).

**Go.** [`debug.SetMemoryLimit`](https://pkg.go.dev/runtime/debug#SetMemoryLimit) · [deprecación de `crypto/elliptic`](https://pkg.go.dev/crypto/elliptic).
