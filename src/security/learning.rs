//! Explicit administrator training; received mail never trains the model automatically.
use super::{db::*, model::*, scan, service::event};
use crate::error::{Result, ensure};
use pratique::json_value::{Value, json};
use std::collections::BTreeSet;
fn tokens(raw: &[u8], settings: &Value) -> Result<BTreeSet<String>> {
    let m = scan::inspect_with_settings(raw, settings)?;
    tokens_inspected(&m)
}
fn tokens_inspected(m: &Value) -> Result<BTreeSet<String>> {
    let text = scan::normalize(&format!("{} {}", s(m, "subject")?, s(m, "text")?));
    Ok(text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| (3..=40).contains(&s.len()))
        .take(4000)
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(512)
        .collect())
}
pub fn score(t: &Table, raw: &[u8], settings: &Value) -> Result<f64> {
    score_tokens(t, tokens(raw, settings)?)
}
pub fn score_inspected(t: &Table, inspected: &Value) -> Result<f64> {
    score_tokens(t, tokens_inspected(inspected)?)
}
fn score_tokens(t: &Table, tokens: BTreeSet<String>) -> Result<f64> {
    let m = get(t, "learning")?.unwrap_or(json!({}));
    let spam = m["spam"].as_u64().unwrap_or(0);
    let ham = m["ham"].as_u64().unwrap_or(0);
    if spam < 20 || ham < 20 {
        return Ok(0.);
    }
    let mut weights = Vec::new();
    for token in tokens {
        if let Some(v) = get(t, &format!("token/{token}"))? {
            let p = (v["spam"].as_u64().unwrap_or(0) as f64 + 1.) / (spam as f64 + 2.);
            let q = (v["ham"].as_u64().unwrap_or(0) as f64 + 1.) / (ham as f64 + 2.);
            weights.push((p / q).ln().clamp(-2., 2.));
        }
    }
    weights.sort_by(|a, b| b.abs().total_cmp(&a.abs()));
    Ok((weights.iter().take(20).sum::<f64>() / 4.).clamp(-3., 5.))
}
pub fn command(t: &mut Table, a: &Actor, action: &str, d: &Value, rid: &str) -> Result<Value> {
    let settings = must(t, "settings")?;
    a.global(&settings)?;
    let mut model = get(t, "learning")?.unwrap_or(json!({"spam":0,"ham":0,"revision":0}));
    if action == "learning" {
        return Ok(json!({"model":model,"minimum_per_class":20,"automatic_training":false}));
    }
    a.require("learn", None)?;
    if action == "learning-reset" {
        ensure!(
            d["confirm"] == true && d["expected_revision"] == model["revision"],
            "Confirm reset of current model revision"
        );
        for prefix in ["token/", "trained/"] {
            for (key, _) in keyed(t, prefix)? {
                remove(t, &key)?;
            }
        }
        model = json!({"spam":0,"ham":0,"revision":n(&model,"revision")?+1});
    } else {
        let m = message(t, s(d, "id")?)?;
        a.require("content", Some(s(&m, "recipient")?))?;
        let class = s(d, "class")?;
        ensure!(["ham", "spam"].contains(&class), "Choose ham or spam");
        let k = format!("trained/{}", s(&m, "hash")?);
        ensure!(
            get(t, &k)?.is_none(),
            "Content already trained; reset the model to relabel"
        );
        ensure!(
            n(&model, "spam")? + n(&model, "ham")? < 50000,
            "Training corpus capacity reached"
        );
        let words = tokens(&body(t, &m)?, &settings)?;
        let mut count = list(t, "token/")?.len();
        for token in words {
            let k = format!("token/{token}");
            let old = get(t, &k)?;
            if old.is_none() {
                count += 1;
            }
            ensure!(count <= 60000, "Vocabulary capacity reached");
            let mut v = old.unwrap_or(json!({"spam":0,"ham":0}));
            v[class] = json!(n(&v, class)? + 1);
            put(t, &k, &v)?;
        }
        model[class] = json!(n(&model, class)? + 1);
        model["revision"] = json!(n(&model, "revision")? + 1);
        put(t, &k, &json!({"class":class,"actor":a.id}))?;
    }
    put(t, "learning", &model)?;
    event(
        t,
        a,
        action,
        rid,
        "",
        json!({"model":model,"message":d["id"],"class":d["class"]}),
    )?;
    Ok(model)
}
