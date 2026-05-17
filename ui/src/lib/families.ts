// Catalogue des 14 familles de mitigations exposées par le control plane.
// Chaque entrée mappe :
//   - id   : segment d'URL (`/v1/mitigations/<id>`)
//   - rid  : id canonique de la règle (souvent identique à id, mais pas
//            toujours — ex. "connections" → règle "default")
//   - label: libellé court affiché dans la sidebar.
//   - desc : description courte (1 ligne) pour le panel.
//   - fields: schéma minimal des params (UI auto-générée).
//
// L'UI est strictement déclarative — ajouter une famille = ajouter une
// entrée ici, pas de code Svelte spécifique à écrire.

export type FieldKind =
  | { kind: 'bool' }
  | { kind: 'int'; min?: number; max?: number }
  | { kind: 'duration' } // string "1s", "100ms"
  | { kind: 'string'; pattern?: string; placeholder?: string }
  | { kind: 'enum'; values: string[] }
  | { kind: 'csv'; itemPattern?: string; placeholder?: string };

export interface FieldDef {
  name: string;
  label: string;
  type: FieldKind;
  hint?: string;
}

export interface FamilyDef {
  id: string;
  rid: string;
  label: string;
  desc: string;
  /** Préfixe des compteurs Prom (ex. `mitigation_slowloris`). */
  metric: string;
  /** Étage du pipeline (0..4) — cf. PIPELINE_STAGES. */
  stage: number;
  fields: FieldDef[];
}

/**
 * Étages du pipeline de mitigation, ordonnés du plus proche du réseau
 * (handshake TLS) à l'analyse comportementale. Sert au rendu Pipeline.
 */
export const PIPELINE_STAGES = [
  { id: 0, label: 'TLS / handshake', desc: 'Renégociations, fingerprint client.' },
  { id: 1, label: 'Connexion', desc: 'Conn per-IP, multiplexing, shedding.' },
  { id: 2, label: 'Hygiène requête', desc: 'Parsing, smuggling, tailles.' },
  { id: 3, label: 'Limites applicatives', desc: 'Token-bucket, ranges, params.' },
  { id: 4, label: 'Comportemental', desc: 'Scraping, credential stuffing.' },
] as const;

export const FAMILIES: FamilyDef[] = [
  {
    id: 'connections',
    rid: 'slowloris',
    label: 'Slowloris',
    desc: 'Limite des connexions per-IP — anti-slowloris.',
    metric: 'mitigation_slowloris',
    stage: 1,
    fields: [
      { name: 'max_conns_per_ip', label: 'Max conns / IP', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'ratelimit',
    rid: 'http-flood-l7',
    label: 'HTTP flood L7',
    desc: 'Token-bucket per-IP — anti-flood applicatif.',
    metric: 'mitigation_http_flood_l7',
    stage: 3,
    fields: [
      { name: 'requests_per_second', label: 'Req/s', type: { kind: 'int', min: 0 } },
      { name: 'burst', label: 'Burst', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'headers',
    rid: 'large-header',
    label: 'Large header',
    desc: 'Bornage taille des en-têtes — anti large-header DoS.',
    metric: 'mitigation_large_header',
    stage: 2,
    fields: [
      { name: 'max_header_bytes', label: 'Max header bytes', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'bodies',
    rid: 'slow-post',
    label: 'Slow POST',
    desc: 'Débit minimum sur le corps — anti slow-post / R-U-Dead-Yet.',
    metric: 'mitigation_slow_post',
    stage: 2,
    fields: [
      { name: 'min_bytes_per_second', label: 'Min B/s', type: { kind: 'int', min: 0 } },
      { name: 'grace', label: 'Grace', type: { kind: 'duration' } },
    ],
  },
  {
    id: 'tls',
    rid: 'tls-renegotiation-flood',
    label: 'TLS reneg flood',
    desc: 'Limite renégociations TLS per-IP.',
    metric: 'mitigation_tls_renegotiation_flood',
    stage: 0,
    fields: [
      { name: 'max_renegotiations_per_minute', label: 'Reneg / min', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'http2',
    rid: 'http2-rapid-reset',
    label: 'HTTP/2 rapid reset',
    desc: 'CVE-2023-44487 — anti rapid-reset.',
    metric: 'mitigation_http2_rapid_reset',
    stage: 1,
    fields: [
      { name: 'max_resets_per_second', label: 'RST/s', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'hash-flood',
    rid: 'hash-flood',
    label: 'Hash flood',
    desc: 'Cardinalité params / form-data — anti collision dict.',
    metric: 'mitigation_hash_flood',
    stage: 3,
    fields: [
      { name: 'max_params', label: 'Max query params', type: { kind: 'int', min: 0 } },
      { name: 'max_form_fields', label: 'Max form fields', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'range-amp',
    rid: 'range-amp',
    label: 'Range amplification',
    desc: 'Anti CVE-2007-0086 / multi-Range chaotique.',
    metric: 'mitigation_range_amp',
    stage: 3,
    fields: [
      { name: 'max_ranges', label: 'Max ranges', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'cache-poison',
    rid: 'cache-poison',
    label: 'Cache poisoning',
    desc: "Validation Host/X-Forwarded-* — anti cache deception.",
    metric: 'mitigation_cache_poison',
    stage: 3,
    fields: [
      { name: 'allowed_hosts', label: 'Hosts autorisés', type: { kind: 'csv', placeholder: 'example.com,www.example.com' } },
    ],
  },
  {
    id: 'scraping',
    rid: 'scraping',
    label: 'Scraping agressif',
    desc: 'Signature UA + en-têtes manquants.',
    metric: 'mitigation_scraping',
    stage: 4,
    fields: [
      { name: 'user_agent_deny', label: 'UA blacklist', type: { kind: 'csv', placeholder: 'curl,python-requests' } },
      { name: 'require_accept_language', label: 'Exige Accept-Language', type: { kind: 'bool' } },
      { name: 'require_accept_encoding', label: 'Exige Accept-Encoding', type: { kind: 'bool' } },
      { name: 'action', label: 'Action', type: { kind: 'enum', values: ['log', 'deny'] } },
    ],
  },
  {
    id: 'credential-stuffing',
    rid: 'credential-stuffing',
    label: 'Credential stuffing',
    desc: 'Bucket per-IP sur endpoints auth + blocklist.',
    metric: 'mitigation_credential_stuffing',
    stage: 4,
    fields: [
      { name: 'requests_per_minute', label: 'Req/min', type: { kind: 'int', min: 0 } },
      { name: 'burst', label: 'Burst', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'concurrency',
    rid: 'concurrency-cap',
    label: 'Concurrency cap',
    desc: 'Load shedding global (in-flight max).',
    metric: 'mitigation_concurrency_cap',
    stage: 1,
    fields: [
      { name: 'max_in_flight', label: 'Max in-flight', type: { kind: 'int', min: 0 } },
    ],
  },
  {
    id: 'request-hygiene',
    rid: 'request-hygiene',
    label: 'Request hygiene',
    desc: 'Méthode whitelist + anti smuggling + Host non vide.',
    metric: 'mitigation_request_hygiene',
    stage: 2,
    fields: [
      { name: 'allowed_methods', label: 'Méthodes', type: { kind: 'csv', itemPattern: '^[A-Z]+$', placeholder: 'GET,POST,HEAD' } },
      { name: 'max_uri_length', label: 'Max URI bytes', type: { kind: 'int', min: 0, max: 1048576 } },
      { name: 'reject_te_cl_conflict', label: 'Reject TE+CL', type: { kind: 'bool' } },
      { name: 'reject_duplicate_content_length', label: 'Reject dup CL', type: { kind: 'bool' } },
      { name: 'reject_invalid_transfer_encoding', label: 'Reject bad TE', type: { kind: 'bool' } },
      { name: 'reject_empty_host', label: 'Reject empty Host', type: { kind: 'bool' } },
    ],
  },
  {
    id: 'tls-fingerprint',
    rid: 'tls-fingerprint',
    label: 'TLS fingerprint',
    desc: 'JA3 + JA4 blocklist au handshake (dormant sans TLS terminé).',
    metric: 'mitigation_tls_fingerprint',
    stage: 0,
    fields: [
      { name: 'blocked_ja3', label: 'JA3 bloqués', type: { kind: 'csv', itemPattern: '^[a-f0-9]{32}$', placeholder: 'hash1,hash2' } },
      { name: 'blocked_ja4', label: 'JA4 bloqués', type: { kind: 'csv', placeholder: 't13d1517h2_8daa..._b186...' } },
    ],
  },
];

export function familyById(id: string): FamilyDef | undefined {
  return FAMILIES.find((f) => f.id === id);
}
