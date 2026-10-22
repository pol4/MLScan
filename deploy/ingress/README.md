# Переход MLScan с NodePort на Ingress/Egress

Единая точка входа — **Istio Ingress Gateway** (вместо per-service NodePort); egress
платформенных сервисов — **allowlist** (deny-by-default). Реализовано в `deploy/ingress/`.

## Было → стало

| Было (NodePort) | Стало (Ingress, Istio) |
|-----------------|------------------------|
| `mlscan-analytics` :30808 | `http://<node>:30217` c `Host: analytics.mlscan.local` |
| `mlscan-integrations` :30809 | `Host: integrations.mlscan.local` |
| `mlscan-ops` :30810 | `Host: ops.mlscan.local` |
| `mlscan-testing-api` :30811 | `Host: api.mlscan.local` |
| egress платформы — открыт | egress — deny-by-default + DNS + только кластерный трафик |

Сервисы MLScan переведены в **ClusterIP**; NodePort у них не остаётся. Наружу торчит только
HTTP-порт **istio-ingressgateway** (NodePort `30217`, HTTPS `30921`) — общий для кластера.

## Как устроено

- **Gateway** `mlscan-ingress/mlscan-gateway` (селектор `istio: ingressgateway`), HTTP :80,
  хосты `analytics|integrations|ops|api.mlscan.local`.
- **VirtualServices** в namespace каждого сервиса → ClusterIP-сервисы (`<svc>.<ns>.svc...:8080`).
- **Egress NetworkPolicy** (`mlscan-egress`) в `mlscan-testing/analytics/integrations/ops`:
  запрет наружу; разрешены DNS и кластерные CIDR (`10.152.0.0/16`, `10.1.0.0/16`);
  для `mlscan-testing` дополнительно разрешён Kubernetes API и порт S3 (3900). Адрес API-endpoint
  определяется автоматически при применении (`apply.sh`: EndpointSlice → Endpoints → ClusterIP
  сервиса `kubernetes`) и подставляется вместо плейсхолдера `198.51.100.10`; если адрес определить
  не удалось, правило отключается (зарезервированный `240.0.0.0/32`), а приложение **падает с
  ошибкой**, если плейсхолдер всё же остался в применённой политике — иначе сервисы теряют доступ
  к Kubernetes API и сканы завершаются таймаутом.

**Осторожно (важно для k8s 1.33+):** устаревший `kubectl get endpoints kubernetes` в 1.33 удалён;
используйте EndpointSlice. Симптом ошибки, если правило для API настроено неверно: сканы падают с
`ошибка сервиса тестирования: TimeoutError: timed out` (сервис не может создать Job песочницы).

### TLS (опционально): HTTPS рядом с HTTP

По умолчанию Gateway слушает **только HTTP** (`http://analytics.mlscan.local:30217`). Если открыть
UI по `https://…:30217`, браузер отправит TLS-хендшейк на HTTP-порт, получит HTTP-ответ и покажет
**`SSL_ERROR_RX_RECORD_TOO_LONG`** (в логах шлюза это видно как `http1.codec_error`/400). Это не
поломка сервиса — просто неверная схема для этого порта.

Включается одной командой:

```bash
bash deploy/install.sh 3 --with-tls        # или: NODE_IP=<ip> bash deploy/ingress/40-tls.sh
```

Что делает `40-tls.sh`:

* генерирует **самоподписанный** сертификат (`CN=mlscan.local`, SAN `DNS:mlscan.local`,
  `DNS:*.mlscan.local`, `IP:<node>`);
* создаёт Secret `mlscan-tls` в `mlscan-ingress` **и в `istio-system`** — общий
  `istio-ingressgateway` читает TLS-секрет по `credentialName` из своего namespace (иначе в логах
  `filter_chain_not_found` на 8443 и «initial fetch timed out … tls.v3.Secret»);
* добавляет в `mlscan-gateway` HTTPS-сервер (:443, `tls.mode=SIMPLE`, `credentialName=mlscan-tls`).

Адреса после включения:

| Схема | Адрес | Примечание |
|-------|-------|------------|
| HTTP | `http://analytics.mlscan.local:30217` | работает всегда (CI/скрипты) |
| HTTPS | `https://analytics.mlscan.local:30921` | самоподписанный сертификат → предупреждение браузера ожидаемо; **нужен Hostname (SNI), не IP** |

Для доверенного сертификата положите свой Secret и передайте его: `SECRET=my-tls bash deploy/ingress/40-tls.sh`.
При удалении MLScan не забудьте убрать наш Secret из общего namespace:
`kubectl -n istio-system delete secret mlscan-tls`.

### Файлы по уровням

Манифесты разделены по уровням, чтобы `install.sh N` работал на любом уровне и после апгрейда:

| Файл | Уровень | Объекты |
|------|---------|---------|
| `00-namespace.yaml`, `10-gateway.yaml` | 3 | namespace `mlscan-ingress`, Gateway |
| `20-virtualservices.yaml` | 3 | VirtualServices: analytics, api (testing) |
| `21-virtualservices-l4.yaml` / `22-virtualservices-l5.yaml` | 4 / 5 | VirtualServices: integrations / ops |
| `30-egress-networkpolicies.yaml` | 3 | egress-политики: testing, analytics |
| `31-egress-networkpolicies-l4.yaml` / `32-egress-networkpolicies-l5.yaml` | 4 / 5 | egress: integrations / ops |

`apply.sh` применяет файл уровня только если соответствующий namespace существует (иначе печатает
подсказку), поэтому более низкие уровни не ломаются.
- Песочница `mlscan-sandbox` сохраняет собственную строгую политику (default-deny + sinkhole
  + artifact-сервер :8090).

## Применение

```bash
bash deploy/ingress/apply.sh
bash deploy/ingress/verify.sh
```

## Проверка (с рабочей станции)

```bash
GW=<NODE_IP>:30217
curl -sS --noproxy '*' -H 'Host: analytics.mlscan.local'    http://$GW/healthz
curl -sS --noproxy '*' -H 'Host: integrations.mlscan.local' http://$GW/healthz
curl -sS --noproxy '*' -H 'Host: ops.mlscan.local'          http://$GW/healthz
curl -sS --noproxy '*' -H 'Host: api.mlscan.local'          http://$GW/healthz

# egress: аналитика не ходит в интернет, но доступна до сервиса тестирования
kubectl -n mlscan-analytics exec deploy/mlscan-analytics -- python -c "import socket;s=socket.socket();s.settimeout(3);
try: s.connect(('1.1.1.1',443)); print('OK')
except Exception as e: print('DENY',type(e).__name__)"
```

Результат проверок: все 4 хоста `→ 200` через шлюз; у MLScan нет NodePort; egress:
`1.1.1.1:443 → DENY`, `mlscan-testing:8080 → OK`.

## Браузер

Добавьте в hosts-файл (или DNS/прокси):

```
<NODE_IP> analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local
```

и открывайте `http://analytics.mlscan.local:30217` (порт шлюза).

## Откат (rollback) к NodePort

Верните тип сервисов и NodePort-порты в `deploy/stage2..stage5/*service*.yaml`
(`type: NodePort` + `nodePort: 308xx`), удалите Gateway/VirtualServices:

```bash
kubectl delete -f deploy/ingress/20-virtualservices.yaml
kubectl delete -f deploy/ingress/10-gateway.yaml
kubectl apply -f deploy/stage2/30-service.yaml -f deploy/stage3/30-service.yaml \
  -f deploy/stage4/30-service.yaml -f deploy/stage5/20-service.yaml
```

## Дальнейшие шаги

- **TLS**: HTTPS-сервер на Gateway с `credentialName` (secret в `istio-system`/ns), редирект
  HTTP→HTTPS. Тестовый самоподписанный сертификат или cert-manager.
- **DNS**: реальные записи вместо `*.mlscan.local` + hosts.
- **AuthN/Z**: JWT/OIDC (RequestAuthentication + AuthorizationPolicy) перед UI/API.
- **Egress**: FQDN-allowlist (Calico `fqdn` в NetworkPolicy) или Egress Gateway для точечного
  доступа к внешним фидам threat-intel; журналирование egress.
- Отдельный namespace `mlscan-ingress` уже выделен (в нём Gateway).
