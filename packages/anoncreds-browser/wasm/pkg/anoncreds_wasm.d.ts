/* tslint:disable */
/* eslint-disable */

export function create_credential(cred_def_json: string, cred_def_private_json: string, credential_offer_json: string, credential_request_json: string, attribute_raw_values_json: string, attribute_encoded_values_json?: string | null, rev_reg_def_json?: string | null, rev_reg_def_private_json?: string | null, rev_status_list_json?: string | null, registry_index?: number | null): string;

export function create_credential_definition(schema_id: string, schema_json: string, tag: string, issuer_id: string, signature_type: string, support_revocation: boolean): string;

export function create_credential_offer(schema_id: string, cred_def_id: string, key_correctness_proof_json: string): string;

export function create_credential_request(entropy: string | null | undefined, prover_did: string | null | undefined, cred_def_json: string, link_secret: string, link_secret_id: string, credential_offer_json: string): string;

export function create_link_secret(): string;

export function create_or_update_revocation_state(rev_reg_def_json: string, rev_status_list_json: string, rev_reg_index: number, tails_bytes: Uint8Array | null | undefined, tails_path: string, old_rev_state_json?: string | null, old_rev_status_list_json?: string | null): string;

export function create_presentation(presentation_request_json: string, credentials_json: string, credentials_prove_json: string, self_attest_json: string, link_secret: string, schemas_json: string, cred_defs_json: string): string;

export function create_revocation_registry_definition(cred_def_json: string, cred_def_id: string, tag: string, rev_reg_type: string, max_cred_num: number): string;

export function create_revocation_status_list(cred_def_json: string, rev_reg_def_id: string, rev_reg_def_json: string, rev_reg_def_private_json: string, issuance_by_default: boolean, timestamp?: bigint | null): string;

export function create_schema(name: string, schema_version: string, issuer_id: string, attribute_names: string[]): string;

export function create_w3c_credential(cred_def_json: string, cred_def_private_json: string, credential_offer_json: string, credential_request_json: string, attribute_raw_values_json: string, rev_reg_def_json?: string | null, rev_reg_def_private_json?: string | null, rev_status_list_json?: string | null, registry_index?: number | null, w3c_version?: string | null): string;

export function create_w3c_presentation(presentation_request_json: string, credentials_json: string, credentials_prove_json: string, link_secret: string, schemas_json: string, cred_defs_json: string, w3c_version?: string | null): string;

export function credential_from_w3c(credential_json: string): string;

export function credential_get_attribute(credential_json: string, name: string): string | undefined;

export function credential_to_w3c(credential_json: string, issuer_id: string, w3c_version?: string | null): string;

export function encode_credential_attributes(attribute_raw_values: string[]): string[];

export function generate_nonce(): string;

/**
 * Returns the tails file bytes for a hash produced by create_revocation_registry_definition
 */
export function get_tails_file(tails_hash: string): Uint8Array | undefined;

/**
 * Parses and validates the JSON for the given object type, returning canonical JSON.
 * Mirrors the native `*_from_json` FFI functions.
 */
export function object_from_json(type_name: string, json: string): string;

export function process_credential(credential_json: string, credential_request_metadata_json: string, link_secret: string, cred_def_json: string, rev_reg_def_json?: string | null): string;

export function process_w3c_credential(credential_json: string, credential_request_metadata_json: string, link_secret: string, cred_def_json: string, rev_reg_def_json?: string | null): string;

export function revocation_registry_definition_get_attribute(rev_reg_def_json: string, name: string): string;

export function start(): void;

export function update_revocation_status_list(cred_def_json: string, rev_reg_def_json: string, rev_reg_def_private_json: string, current_list_json: string, issued?: Uint32Array | null, revoked?: Uint32Array | null, timestamp?: bigint | null): string;

export function update_revocation_status_list_timestamp_only(timestamp: bigint, current_list_json: string): string;

export function verify_presentation(presentation_json: string, presentation_request_json: string, schemas_json: string, cred_defs_json: string, rev_reg_defs_json?: string | null, rev_status_lists_json?: string | null, nonrevoked_interval_overrides_json?: string | null): boolean;

export function verify_w3c_presentation(presentation_json: string, presentation_request_json: string, schemas_json: string, cred_defs_json: string, rev_reg_defs_json?: string | null, rev_status_lists_json?: string | null, nonrevoked_interval_overrides_json?: string | null): boolean;

export function version(): string;

export function w3c_credential_get_integrity_proof_details(credential_json: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly create_credential: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly create_credential_definition: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly create_credential_offer: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly create_credential_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly create_link_secret: () => [number, number, number, number];
    readonly create_or_update_revocation_state: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number, number];
    readonly create_presentation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly create_revocation_registry_definition: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly create_revocation_status_list: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint) => [number, number, number, number];
    readonly create_schema: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly create_w3c_credential: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly create_w3c_presentation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly credential_from_w3c: (a: number, b: number) => [number, number, number, number];
    readonly credential_get_attribute: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly credential_to_w3c: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encode_credential_attributes: (a: number, b: number) => [number, number, number, number];
    readonly generate_nonce: () => [number, number, number, number];
    readonly get_tails_file: (a: number, b: number) => [number, number];
    readonly object_from_json: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly process_credential: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly process_w3c_credential: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly revocation_registry_definition_get_attribute: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly start: () => void;
    readonly update_revocation_status_list: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: bigint) => [number, number, number, number];
    readonly update_revocation_status_list_timestamp_only: (a: bigint, b: number, c: number) => [number, number, number, number];
    readonly verify_presentation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number];
    readonly verify_w3c_presentation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number];
    readonly version: () => [number, number];
    readonly w3c_credential_get_integrity_proof_details: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
