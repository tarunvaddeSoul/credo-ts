//! wasm-bindgen bindings over anoncreds-rs, mirroring the native FFI surface used by
//! @hyperledger/anoncreds-shared. All objects cross the boundary as JSON strings; the
//! TypeScript adapter keeps the handle registry.

mod tails;

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId, SignatureType};
use anoncreds::data_types::issuer_id::IssuerId;
use anoncreds::data_types::rev_reg_def::{RegistryType, RevocationRegistryDefinitionId};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::data_types::w3c::credential::W3CCredential;
use anoncreds::data_types::w3c::presentation::W3CPresentation;
use anoncreds::data_types::w3c::VerifiableCredentialSpecVersion;
use anoncreds::types::{
    Credential, CredentialDefinitionConfig, CredentialDefinitionPrivate,
    CredentialKeyCorrectnessProof, CredentialOffer, CredentialRequest, CredentialRequestMetadata,
    CredentialRevocationConfig, CredentialRevocationState, CredentialValues, LinkSecret,
    MakeCredentialValues, PresentCredentials, Presentation, PresentationRequest,
    RevocationRegistry, RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate,
    RevocationStatusList,
};
use anoncreds::w3c::types::MakeCredentialAttributes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use tails::{MemoryTailsReader, MemoryTailsWriter};

pub const ANONCREDS_VERSION: &str = "0.2.3";

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

fn js_err(context: &str, error: impl std::fmt::Display) -> JsError {
    JsError::new(&format!("{context}: {error}"))
}

fn parse<T: DeserializeOwned>(label: &str, json: &str) -> Result<T, JsError> {
    serde_json::from_str(json).map_err(|e| js_err(&format!("Error parsing {label}"), e))
}

fn parse_opt<T: DeserializeOwned>(label: &str, json: Option<String>) -> Result<Option<T>, JsError> {
    json.map(|j| parse(label, &j)).transpose()
}

fn ser<T: Serialize>(label: &str, value: &T) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|e| js_err(&format!("Error serializing {label}"), e))
}

fn parse_map<T: DeserializeOwned, K, E>(
    label: &str,
    json: &str,
    make_key: impl Fn(&str) -> Result<K, E>,
) -> Result<HashMap<K, T>, JsError>
where
    K: std::hash::Hash + Eq,
    E: std::fmt::Display,
{
    let raw: HashMap<String, String> = parse(label, json)?;
    let mut out = HashMap::with_capacity(raw.len());
    for (id, value_json) in raw {
        let key = make_key(&id).map_err(|e| js_err(&format!("Invalid id in {label}"), e))?;
        out.insert(key, parse(label, &value_json)?);
    }
    Ok(out)
}

fn multi_object_result(parts: &[(&str, String)]) -> Result<String, JsError> {
    let map: HashMap<&str, &str> = parts.iter().map(|(k, v)| (*k, v.as_str())).collect();
    ser("result", &map)
}

#[wasm_bindgen]
pub fn version() -> String {
    ANONCREDS_VERSION.to_string()
}

#[wasm_bindgen]
pub fn generate_nonce() -> Result<String, JsError> {
    let nonce = anoncreds::verifier::generate_nonce().map_err(|e| js_err("generate_nonce", e))?;
    Ok(nonce.to_string())
}

#[wasm_bindgen]
pub fn create_link_secret() -> Result<String, JsError> {
    let secret = anoncreds::prover::create_link_secret().map_err(|e| js_err("create_link_secret", e))?;
    let secret: String = secret
        .try_into()
        .map_err(|e| js_err("create_link_secret", e))?;
    Ok(secret)
}

#[wasm_bindgen]
pub fn encode_credential_attributes(attribute_raw_values: Vec<String>) -> Result<Vec<String>, JsError> {
    let mut encoded = Vec::with_capacity(attribute_raw_values.len());
    for raw in attribute_raw_values {
        let mut values = MakeCredentialValues::default();
        values
            .add_raw("attribute", &raw)
            .map_err(|e| js_err("encode_credential_attributes", e))?;
        let values: CredentialValues = values.into();
        let value = values
            .0
            .get("attribute")
            .ok_or_else(|| JsError::new("encode_credential_attributes: missing value"))?;
        encoded.push(value.encoded.clone());
    }
    Ok(encoded)
}

#[wasm_bindgen]
pub fn create_schema(
    name: &str,
    schema_version: &str,
    issuer_id: &str,
    attribute_names: Vec<String>,
) -> Result<String, JsError> {
    let issuer_id = IssuerId::new(issuer_id).map_err(|e| js_err("Invalid issuerId", e))?;
    let schema = anoncreds::issuer::create_schema(name, schema_version, issuer_id, attribute_names.into())
        .map_err(|e| js_err("create_schema", e))?;
    ser("schema", &schema)
}

#[wasm_bindgen]
pub fn create_credential_definition(
    schema_id: &str,
    schema_json: &str,
    tag: &str,
    issuer_id: &str,
    signature_type: &str,
    support_revocation: bool,
) -> Result<String, JsError> {
    let schema_id = SchemaId::new(schema_id).map_err(|e| js_err("Invalid schemaId", e))?;
    let schema: Schema = parse("schema", schema_json)?;
    let issuer_id = IssuerId::new(issuer_id).map_err(|e| js_err("Invalid issuerId", e))?;
    let signature_type =
        SignatureType::from_str(signature_type).map_err(|e| js_err("Invalid signatureType", e))?;

    let (cred_def, cred_def_private, key_correctness_proof) =
        anoncreds::issuer::create_credential_definition(
            schema_id,
            &schema,
            issuer_id,
            tag,
            signature_type,
            CredentialDefinitionConfig::new(support_revocation),
        )
        .map_err(|e| js_err("create_credential_definition", e))?;

    multi_object_result(&[
        ("credentialDefinition", ser("credentialDefinition", &cred_def)?),
        ("credentialDefinitionPrivate", ser("credentialDefinitionPrivate", &cred_def_private)?),
        ("keyCorrectnessProof", ser("keyCorrectnessProof", &key_correctness_proof)?),
    ])
}

#[wasm_bindgen]
pub fn create_credential_offer(
    schema_id: &str,
    cred_def_id: &str,
    key_correctness_proof_json: &str,
) -> Result<String, JsError> {
    let schema_id = SchemaId::new(schema_id).map_err(|e| js_err("Invalid schemaId", e))?;
    let cred_def_id =
        CredentialDefinitionId::new(cred_def_id).map_err(|e| js_err("Invalid credentialDefinitionId", e))?;
    let key_correctness_proof: CredentialKeyCorrectnessProof =
        parse("keyCorrectnessProof", key_correctness_proof_json)?;

    let offer = anoncreds::issuer::create_credential_offer(schema_id, cred_def_id, &key_correctness_proof)
        .map_err(|e| js_err("create_credential_offer", e))?;
    ser("credentialOffer", &offer)
}

#[wasm_bindgen]
pub fn create_credential_request(
    entropy: Option<String>,
    prover_did: Option<String>,
    cred_def_json: &str,
    link_secret: &str,
    link_secret_id: &str,
    credential_offer_json: &str,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let link_secret = LinkSecret::try_from(link_secret).map_err(|e| js_err("Invalid linkSecret", e))?;
    let credential_offer: CredentialOffer = parse("credentialOffer", credential_offer_json)?;

    let (cred_request, cred_request_metadata) = anoncreds::prover::create_credential_request(
        entropy.as_deref(),
        prover_did.as_deref(),
        &cred_def,
        &link_secret,
        link_secret_id,
        &credential_offer,
    )
    .map_err(|e| js_err("create_credential_request", e))?;

    multi_object_result(&[
        ("credentialRequest", ser("credentialRequest", &cred_request)?),
        ("credentialRequestMetadata", ser("credentialRequestMetadata", &cred_request_metadata)?),
    ])
}

struct RevocationConfigParts {
    reg_def: RevocationRegistryDefinition,
    reg_def_private: RevocationRegistryDefinitionPrivate,
    status_list: RevocationStatusList,
    registry_idx: u32,
}

fn parse_revocation_config(
    rev_reg_def_json: Option<String>,
    rev_reg_def_private_json: Option<String>,
    rev_status_list_json: Option<String>,
    registry_index: Option<u32>,
) -> Result<Option<RevocationConfigParts>, JsError> {
    match (rev_reg_def_json, rev_reg_def_private_json, rev_status_list_json, registry_index) {
        (None, None, None, None) => Ok(None),
        (Some(reg_def), Some(reg_def_private), Some(status_list), Some(registry_idx)) => {
            Ok(Some(RevocationConfigParts {
                reg_def: parse("revocationRegistryDefinition", &reg_def)?,
                reg_def_private: parse("revocationRegistryDefinitionPrivate", &reg_def_private)?,
                status_list: parse("revocationStatusList", &status_list)?,
                registry_idx,
            }))
        }
        _ => Err(JsError::new(
            "Incomplete revocation configuration: definition, private definition, status list and registry index are all required",
        )),
    }
}

fn build_credential_values(
    attribute_raw_values_json: &str,
    attribute_encoded_values_json: Option<String>,
) -> Result<CredentialValues, JsError> {
    let raw_values: HashMap<String, String> = parse("attributeRawValues", attribute_raw_values_json)?;
    let encoded_values: Option<HashMap<String, String>> =
        parse_opt("attributeEncodedValues", attribute_encoded_values_json)?;

    let mut values = MakeCredentialValues::default();
    for (name, raw) in raw_values {
        match encoded_values.as_ref().and_then(|e| e.get(&name)) {
            Some(encoded) => values.add_encoded(name, raw, encoded.clone()),
            None => values
                .add_raw(name, raw)
                .map_err(|e| js_err("Error encoding attribute", e))?,
        }
    }
    Ok(values.into())
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_credential(
    cred_def_json: &str,
    cred_def_private_json: &str,
    credential_offer_json: &str,
    credential_request_json: &str,
    attribute_raw_values_json: &str,
    attribute_encoded_values_json: Option<String>,
    rev_reg_def_json: Option<String>,
    rev_reg_def_private_json: Option<String>,
    rev_status_list_json: Option<String>,
    registry_index: Option<u32>,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let cred_def_private: CredentialDefinitionPrivate =
        parse("credentialDefinitionPrivate", cred_def_private_json)?;
    let credential_offer: CredentialOffer = parse("credentialOffer", credential_offer_json)?;
    let credential_request: CredentialRequest = parse("credentialRequest", credential_request_json)?;
    let values = build_credential_values(attribute_raw_values_json, attribute_encoded_values_json)?;
    let revocation = parse_revocation_config(
        rev_reg_def_json,
        rev_reg_def_private_json,
        rev_status_list_json,
        registry_index,
    )?;

    let credential = anoncreds::issuer::create_credential(
        &cred_def,
        &cred_def_private,
        &credential_offer,
        &credential_request,
        values,
        revocation.as_ref().map(|r| CredentialRevocationConfig {
            reg_def: &r.reg_def,
            reg_def_private: &r.reg_def_private,
            status_list: &r.status_list,
            registry_idx: r.registry_idx,
        }),
    )
    .map_err(|e| js_err("create_credential", e))?;

    ser("credential", &credential)
}

#[wasm_bindgen]
pub fn process_credential(
    credential_json: &str,
    credential_request_metadata_json: &str,
    link_secret: &str,
    cred_def_json: &str,
    rev_reg_def_json: Option<String>,
) -> Result<String, JsError> {
    let mut credential: Credential = parse("credential", credential_json)?;
    let cred_request_metadata: CredentialRequestMetadata =
        parse("credentialRequestMetadata", credential_request_metadata_json)?;
    let link_secret = LinkSecret::try_from(link_secret).map_err(|e| js_err("Invalid linkSecret", e))?;
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let rev_reg_def: Option<RevocationRegistryDefinition> =
        parse_opt("revocationRegistryDefinition", rev_reg_def_json)?;

    anoncreds::prover::process_credential(
        &mut credential,
        &cred_request_metadata,
        &link_secret,
        &cred_def,
        rev_reg_def.as_ref(),
    )
    .map_err(|e| js_err("process_credential", e))?;

    ser("credential", &credential)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialEntryIn {
    credential: String,
    timestamp: Option<u64>,
    revocation_state: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialProveIn {
    entry_index: usize,
    referent: String,
    is_predicate: bool,
    reveal: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NonRevokedIntervalOverrideIn {
    revocation_registry_definition_id: String,
    requested_from_timestamp: u64,
    override_revocation_status_list_timestamp: u64,
}

struct ParsedEntry<T> {
    credential: T,
    timestamp: Option<u64>,
    revocation_state: Option<CredentialRevocationState>,
}

fn parse_entries<T: DeserializeOwned>(credentials_json: &str) -> Result<Vec<ParsedEntry<T>>, JsError> {
    let entries: Vec<CredentialEntryIn> = parse("credentials", credentials_json)?;
    entries
        .into_iter()
        .map(|entry| {
            Ok(ParsedEntry {
                credential: parse("credential", &entry.credential)?,
                timestamp: entry.timestamp,
                revocation_state: entry
                    .revocation_state
                    .as_deref()
                    .map(|json| parse("revocationState", json))
                    .transpose()?,
            })
        })
        .collect()
}

fn build_present_credentials<'a, T>(
    entries: &'a [ParsedEntry<T>],
    prove_json: &str,
) -> Result<PresentCredentials<'a, T>, JsError> {
    let proves: Vec<CredentialProveIn> = parse("credentialsProve", prove_json)?;
    let mut present = PresentCredentials::default();
    for (idx, entry) in entries.iter().enumerate() {
        let mut add_cred = present.add_credential(
            &entry.credential,
            entry.timestamp,
            entry.revocation_state.as_ref(),
        );
        for prove in proves.iter().filter(|p| p.entry_index == idx) {
            if prove.is_predicate {
                add_cred.add_requested_predicate(prove.referent.clone());
            } else {
                add_cred.add_requested_attribute(prove.referent.clone(), prove.reveal);
            }
        }
    }
    Ok(present)
}

fn parse_schemas(schemas_json: &str) -> Result<HashMap<SchemaId, Schema>, JsError> {
    parse_map("schemas", schemas_json, |s: &str| SchemaId::new(s.to_owned()))
}

fn parse_cred_defs(
    cred_defs_json: &str,
) -> Result<HashMap<CredentialDefinitionId, CredentialDefinition>, JsError> {
    parse_map("credentialDefinitions", cred_defs_json, |s: &str| {
        CredentialDefinitionId::new(s.to_owned())
    })
}

fn parse_rev_reg_defs(
    json: Option<String>,
) -> Result<Option<HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>, JsError> {
    json.map(|j| {
        parse_map("revocationRegistryDefinitions", &j, |s: &str| {
            RevocationRegistryDefinitionId::new(s.to_owned())
        })
    })
    .transpose()
}

fn parse_status_lists(json: Option<String>) -> Result<Option<Vec<RevocationStatusList>>, JsError> {
    let lists: Option<Vec<String>> = parse_opt("revocationStatusLists", json)?;
    lists
        .map(|lists| {
            lists
                .iter()
                .map(|list| parse("revocationStatusList", list))
                .collect()
        })
        .transpose()
}

fn parse_interval_overrides(
    json: Option<String>,
) -> Result<Option<HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>>, JsError> {
    let overrides: Option<Vec<NonRevokedIntervalOverrideIn>> =
        parse_opt("nonRevokedIntervalOverrides", json)?;
    overrides
        .map(|entries| {
            let mut map: HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>> = HashMap::new();
            for entry in entries {
                let id = RevocationRegistryDefinitionId::new(&entry.revocation_registry_definition_id)
                    .map_err(|e| js_err("Invalid revocationRegistryDefinitionId", e))?;
                map.entry(id).or_default().insert(
                    entry.requested_from_timestamp,
                    entry.override_revocation_status_list_timestamp,
                );
            }
            Ok(map)
        })
        .transpose()
}

#[wasm_bindgen]
pub fn create_presentation(
    presentation_request_json: &str,
    credentials_json: &str,
    credentials_prove_json: &str,
    self_attest_json: &str,
    link_secret: &str,
    schemas_json: &str,
    cred_defs_json: &str,
) -> Result<String, JsError> {
    let pres_req: PresentationRequest = parse("presentationRequest", presentation_request_json)?;
    let entries = parse_entries::<Credential>(credentials_json)?;
    let present = build_present_credentials(&entries, credentials_prove_json)?;
    let self_attested: HashMap<String, String> = parse("selfAttest", self_attest_json)?;
    let link_secret = LinkSecret::try_from(link_secret).map_err(|e| js_err("Invalid linkSecret", e))?;
    let schemas = parse_schemas(schemas_json)?;
    let cred_defs = parse_cred_defs(cred_defs_json)?;

    let presentation = anoncreds::prover::create_presentation(
        &pres_req,
        present,
        if self_attested.is_empty() { None } else { Some(self_attested) },
        &link_secret,
        &schemas,
        &cred_defs,
    )
    .map_err(|e| js_err("create_presentation", e))?;

    ser("presentation", &presentation)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_presentation(
    presentation_json: &str,
    presentation_request_json: &str,
    schemas_json: &str,
    cred_defs_json: &str,
    rev_reg_defs_json: Option<String>,
    rev_status_lists_json: Option<String>,
    nonrevoked_interval_overrides_json: Option<String>,
) -> Result<bool, JsError> {
    let presentation: Presentation = parse("presentation", presentation_json)?;
    let pres_req: PresentationRequest = parse("presentationRequest", presentation_request_json)?;
    let schemas = parse_schemas(schemas_json)?;
    let cred_defs = parse_cred_defs(cred_defs_json)?;
    let rev_reg_defs = parse_rev_reg_defs(rev_reg_defs_json)?;
    let rev_status_lists = parse_status_lists(rev_status_lists_json)?;
    let overrides = parse_interval_overrides(nonrevoked_interval_overrides_json)?;

    anoncreds::verifier::verify_presentation(
        &presentation,
        &pres_req,
        &schemas,
        &cred_defs,
        rev_reg_defs.as_ref(),
        rev_status_lists,
        overrides.as_ref(),
    )
    .map_err(|e| js_err("verify_presentation", e))
}

#[wasm_bindgen]
pub fn create_revocation_registry_definition(
    cred_def_json: &str,
    cred_def_id: &str,
    tag: &str,
    rev_reg_type: &str,
    max_cred_num: u32,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let cred_def_id =
        CredentialDefinitionId::new(cred_def_id).map_err(|e| js_err("Invalid credentialDefinitionId", e))?;
    let rev_reg_type =
        RegistryType::from_str(rev_reg_type).map_err(|e| js_err("Invalid revocationRegistryType", e))?;

    let mut tails_writer = MemoryTailsWriter;
    let (reg_def, reg_def_private) = anoncreds::issuer::create_revocation_registry_def(
        &cred_def,
        cred_def_id,
        tag,
        rev_reg_type,
        max_cred_num,
        &mut tails_writer,
    )
    .map_err(|e| js_err("create_revocation_registry_definition", e))?;

    multi_object_result(&[
        ("revocationRegistryDefinition", ser("revocationRegistryDefinition", &reg_def)?),
        (
            "revocationRegistryDefinitionPrivate",
            ser("revocationRegistryDefinitionPrivate", &reg_def_private)?,
        ),
    ])
}

/// Returns the tails file bytes for a hash produced by create_revocation_registry_definition
#[wasm_bindgen]
pub fn get_tails_file(tails_hash: &str) -> Option<Vec<u8>> {
    tails::get_tails(tails_hash)
}

#[wasm_bindgen]
pub fn create_revocation_status_list(
    cred_def_json: &str,
    rev_reg_def_id: &str,
    rev_reg_def_json: &str,
    rev_reg_def_private_json: &str,
    issuance_by_default: bool,
    timestamp: Option<u64>,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let rev_reg_def_id = RevocationRegistryDefinitionId::new(rev_reg_def_id)
        .map_err(|e| js_err("Invalid revocationRegistryDefinitionId", e))?;
    let rev_reg_def: RevocationRegistryDefinition =
        parse("revocationRegistryDefinition", rev_reg_def_json)?;
    let rev_reg_def_private: RevocationRegistryDefinitionPrivate =
        parse("revocationRegistryDefinitionPrivate", rev_reg_def_private_json)?;

    let status_list = anoncreds::issuer::create_revocation_status_list(
        &cred_def,
        rev_reg_def_id,
        &rev_reg_def,
        &rev_reg_def_private,
        issuance_by_default,
        timestamp,
    )
    .map_err(|e| js_err("create_revocation_status_list", e))?;

    ser("revocationStatusList", &status_list)
}

#[wasm_bindgen]
pub fn update_revocation_status_list_timestamp_only(
    timestamp: u64,
    current_list_json: &str,
) -> Result<String, JsError> {
    let current_list: RevocationStatusList = parse("revocationStatusList", current_list_json)?;
    let updated =
        anoncreds::issuer::update_revocation_status_list_timestamp_only(timestamp, &current_list);
    ser("revocationStatusList", &updated)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn update_revocation_status_list(
    cred_def_json: &str,
    rev_reg_def_json: &str,
    rev_reg_def_private_json: &str,
    current_list_json: &str,
    issued: Option<Vec<u32>>,
    revoked: Option<Vec<u32>>,
    timestamp: Option<u64>,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let rev_reg_def: RevocationRegistryDefinition =
        parse("revocationRegistryDefinition", rev_reg_def_json)?;
    let rev_reg_def_private: RevocationRegistryDefinitionPrivate =
        parse("revocationRegistryDefinitionPrivate", rev_reg_def_private_json)?;
    let current_list: RevocationStatusList = parse("revocationStatusList", current_list_json)?;

    let updated = anoncreds::issuer::update_revocation_status_list(
        &cred_def,
        &rev_reg_def,
        &rev_reg_def_private,
        &current_list,
        issued.map(BTreeSet::from_iter),
        revoked.map(BTreeSet::from_iter),
        timestamp,
    )
    .map_err(|e| js_err("update_revocation_status_list", e))?;

    ser("revocationStatusList", &updated)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_or_update_revocation_state(
    rev_reg_def_json: &str,
    rev_status_list_json: &str,
    rev_reg_index: u32,
    tails_bytes: Option<Vec<u8>>,
    tails_path: &str,
    old_rev_state_json: Option<String>,
    old_rev_status_list_json: Option<String>,
) -> Result<String, JsError> {
    let rev_reg_def: RevocationRegistryDefinition =
        parse("revocationRegistryDefinition", rev_reg_def_json)?;
    let rev_status_list: RevocationStatusList = parse("revocationStatusList", rev_status_list_json)?;
    let old_rev_state: Option<CredentialRevocationState> =
        parse_opt("revocationState", old_rev_state_json)?;
    let old_rev_status_list: Option<RevocationStatusList> =
        parse_opt("oldRevocationStatusList", old_rev_status_list_json)?;

    let tails_bytes = tails_bytes
        .or_else(|| tails::get_tails(tails_path))
        .or_else(|| tails::get_tails(&rev_reg_def.value.tails_hash))
        .ok_or_else(|| {
            JsError::new(
                "No tails data available: pass the tails file bytes or preload them for this tails hash",
            )
        })?;

    let state = anoncreds::prover::create_or_update_revocation_state_with_reader(
        &MemoryTailsReader(tails_bytes),
        &rev_reg_def,
        &rev_status_list,
        rev_reg_index,
        old_rev_state.as_ref(),
        old_rev_status_list.as_ref(),
    )
    .map_err(|e| js_err("create_or_update_revocation_state", e))?;

    ser("revocationState", &state)
}

#[wasm_bindgen]
pub fn credential_get_attribute(credential_json: &str, name: &str) -> Result<Option<String>, JsError> {
    let credential: Credential = parse("credential", credential_json)?;
    let value = match name {
        "schema_id" => Some(credential.schema_id.to_string()),
        "cred_def_id" => Some(credential.cred_def_id.to_string()),
        "rev_reg_id" => credential.rev_reg_id.as_ref().map(ToString::to_string),
        "rev_reg_index" => credential.signature.extract_index().map(|i| i.to_string()),
        _ => return Err(JsError::new(&format!("Unsupported attribute: {name}"))),
    };
    Ok(value)
}

#[wasm_bindgen]
pub fn revocation_registry_definition_get_attribute(
    rev_reg_def_json: &str,
    name: &str,
) -> Result<String, JsError> {
    let rev_reg_def: RevocationRegistryDefinition =
        parse("revocationRegistryDefinition", rev_reg_def_json)?;
    let value = match name {
        "max_cred_num" => rev_reg_def.value.max_cred_num.to_string(),
        "tails_hash" => rev_reg_def.value.tails_hash,
        "tails_location" => rev_reg_def.value.tails_location,
        _ => return Err(JsError::new(&format!("Unsupported attribute: {name}"))),
    };
    Ok(value)
}

fn parse_w3c_version(version: Option<String>) -> Result<Option<VerifiableCredentialSpecVersion>, JsError> {
    version
        .as_deref()
        .map(|v| VerifiableCredentialSpecVersion::try_from(v).map_err(|e| js_err("Invalid w3cVersion", e)))
        .transpose()
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_w3c_credential(
    cred_def_json: &str,
    cred_def_private_json: &str,
    credential_offer_json: &str,
    credential_request_json: &str,
    attribute_raw_values_json: &str,
    rev_reg_def_json: Option<String>,
    rev_reg_def_private_json: Option<String>,
    rev_status_list_json: Option<String>,
    registry_index: Option<u32>,
    w3c_version: Option<String>,
) -> Result<String, JsError> {
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let cred_def_private: CredentialDefinitionPrivate =
        parse("credentialDefinitionPrivate", cred_def_private_json)?;
    let credential_offer: CredentialOffer = parse("credentialOffer", credential_offer_json)?;
    let credential_request: CredentialRequest = parse("credentialRequest", credential_request_json)?;

    let raw_values: HashMap<String, String> = parse("attributeRawValues", attribute_raw_values_json)?;
    let mut attributes = MakeCredentialAttributes::default();
    for (name, raw) in raw_values {
        attributes.add(name, raw);
    }

    let revocation = parse_revocation_config(
        rev_reg_def_json,
        rev_reg_def_private_json,
        rev_status_list_json,
        registry_index,
    )?;
    let version = parse_w3c_version(w3c_version)?;

    let credential = anoncreds::w3c::issuer::create_credential(
        &cred_def,
        &cred_def_private,
        &credential_offer,
        &credential_request,
        attributes.into(),
        revocation.as_ref().map(|r| CredentialRevocationConfig {
            reg_def: &r.reg_def,
            reg_def_private: &r.reg_def_private,
            status_list: &r.status_list,
            registry_idx: r.registry_idx,
        }),
        version,
    )
    .map_err(|e| js_err("create_w3c_credential", e))?;

    ser("w3cCredential", &credential)
}

#[wasm_bindgen]
pub fn process_w3c_credential(
    credential_json: &str,
    credential_request_metadata_json: &str,
    link_secret: &str,
    cred_def_json: &str,
    rev_reg_def_json: Option<String>,
) -> Result<String, JsError> {
    let mut credential: W3CCredential = parse("w3cCredential", credential_json)?;
    let cred_request_metadata: CredentialRequestMetadata =
        parse("credentialRequestMetadata", credential_request_metadata_json)?;
    let link_secret = LinkSecret::try_from(link_secret).map_err(|e| js_err("Invalid linkSecret", e))?;
    let cred_def: CredentialDefinition = parse("credentialDefinition", cred_def_json)?;
    let rev_reg_def: Option<RevocationRegistryDefinition> =
        parse_opt("revocationRegistryDefinition", rev_reg_def_json)?;

    anoncreds::w3c::prover::process_credential(
        &mut credential,
        &cred_request_metadata,
        &link_secret,
        &cred_def,
        rev_reg_def.as_ref(),
    )
    .map_err(|e| js_err("process_w3c_credential", e))?;

    ser("w3cCredential", &credential)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_w3c_presentation(
    presentation_request_json: &str,
    credentials_json: &str,
    credentials_prove_json: &str,
    link_secret: &str,
    schemas_json: &str,
    cred_defs_json: &str,
    w3c_version: Option<String>,
) -> Result<String, JsError> {
    let pres_req: PresentationRequest = parse("presentationRequest", presentation_request_json)?;
    let entries = parse_entries::<W3CCredential>(credentials_json)?;
    let present = build_present_credentials(&entries, credentials_prove_json)?;
    let link_secret = LinkSecret::try_from(link_secret).map_err(|e| js_err("Invalid linkSecret", e))?;
    let schemas = parse_schemas(schemas_json)?;
    let cred_defs = parse_cred_defs(cred_defs_json)?;
    let version = parse_w3c_version(w3c_version)?;

    let presentation = anoncreds::w3c::prover::create_presentation(
        &pres_req,
        present,
        &link_secret,
        &schemas,
        &cred_defs,
        version,
    )
    .map_err(|e| js_err("create_w3c_presentation", e))?;

    ser("w3cPresentation", &presentation)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_w3c_presentation(
    presentation_json: &str,
    presentation_request_json: &str,
    schemas_json: &str,
    cred_defs_json: &str,
    rev_reg_defs_json: Option<String>,
    rev_status_lists_json: Option<String>,
    nonrevoked_interval_overrides_json: Option<String>,
) -> Result<bool, JsError> {
    let presentation: W3CPresentation = parse("w3cPresentation", presentation_json)?;
    let pres_req: PresentationRequest = parse("presentationRequest", presentation_request_json)?;
    let schemas = parse_schemas(schemas_json)?;
    let cred_defs = parse_cred_defs(cred_defs_json)?;
    let rev_reg_defs = parse_rev_reg_defs(rev_reg_defs_json)?;
    let rev_status_lists = parse_status_lists(rev_status_lists_json)?;
    let overrides = parse_interval_overrides(nonrevoked_interval_overrides_json)?;

    anoncreds::w3c::verifier::verify_presentation(
        &presentation,
        &pres_req,
        &schemas,
        &cred_defs,
        rev_reg_defs.as_ref(),
        rev_status_lists,
        overrides.as_ref(),
    )
    .map_err(|e| js_err("verify_w3c_presentation", e))
}

#[wasm_bindgen]
pub fn credential_to_w3c(
    credential_json: &str,
    issuer_id: &str,
    w3c_version: Option<String>,
) -> Result<String, JsError> {
    let credential: Credential = parse("credential", credential_json)?;
    let issuer_id = IssuerId::new(issuer_id).map_err(|e| js_err("Invalid issuerId", e))?;
    let version = parse_w3c_version(w3c_version)?;

    let w3c_credential =
        anoncreds::w3c::credential_conversion::credential_to_w3c(&credential, &issuer_id, version)
            .map_err(|e| js_err("credential_to_w3c", e))?;
    ser("w3cCredential", &w3c_credential)
}

#[wasm_bindgen]
pub fn credential_from_w3c(credential_json: &str) -> Result<String, JsError> {
    let credential: W3CCredential = parse("w3cCredential", credential_json)?;
    let legacy = anoncreds::w3c::credential_conversion::credential_from_w3c(&credential)
        .map_err(|e| js_err("credential_from_w3c", e))?;
    ser("credential", &legacy)
}

#[wasm_bindgen]
pub fn w3c_credential_get_integrity_proof_details(credential_json: &str) -> Result<String, JsError> {
    let credential: W3CCredential = parse("w3cCredential", credential_json)?;
    let proof = credential
        .get_data_integrity_proof()
        .map_err(|e| js_err("w3c_credential_get_integrity_proof_details", e))?;
    let details = proof
        .get_credential_proof_details()
        .map_err(|e| js_err("w3c_credential_get_integrity_proof_details", e))?;
    ser("credentialProofDetails", &details)
}

/// Parses and validates the JSON for the given object type, returning canonical JSON.
/// Mirrors the native `*_from_json` FFI functions.
#[wasm_bindgen]
pub fn object_from_json(type_name: &str, json: &str) -> Result<String, JsError> {
    fn roundtrip<T: DeserializeOwned + Serialize>(label: &str, json: &str) -> Result<String, JsError> {
        let value: T = parse(label, json)?;
        ser(label, &value)
    }

    match type_name {
        "Schema" => roundtrip::<Schema>(type_name, json),
        "CredentialDefinition" => roundtrip::<CredentialDefinition>(type_name, json),
        "CredentialDefinitionPrivate" => roundtrip::<CredentialDefinitionPrivate>(type_name, json),
        "KeyCorrectnessProof" => roundtrip::<CredentialKeyCorrectnessProof>(type_name, json),
        "CredentialOffer" => roundtrip::<CredentialOffer>(type_name, json),
        "CredentialRequest" => roundtrip::<CredentialRequest>(type_name, json),
        "CredentialRequestMetadata" => roundtrip::<CredentialRequestMetadata>(type_name, json),
        "Credential" => roundtrip::<Credential>(type_name, json),
        "W3CCredential" => roundtrip::<W3CCredential>(type_name, json),
        "Presentation" => roundtrip::<Presentation>(type_name, json),
        "W3CPresentation" => roundtrip::<W3CPresentation>(type_name, json),
        "PresentationRequest" => roundtrip::<PresentationRequest>(type_name, json),
        "RevocationRegistryDefinition" => roundtrip::<RevocationRegistryDefinition>(type_name, json),
        "RevocationRegistryDefinitionPrivate" => {
            roundtrip::<RevocationRegistryDefinitionPrivate>(type_name, json)
        }
        "RevocationRegistry" => roundtrip::<RevocationRegistry>(type_name, json),
        "RevocationStatusList" => roundtrip::<RevocationStatusList>(type_name, json),
        "CredentialRevocationState" => roundtrip::<CredentialRevocationState>(type_name, json),
        _ => Err(JsError::new(&format!("Unsupported object type: {type_name}"))),
    }
}
