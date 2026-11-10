"""Worker de conversão Sigma → backends. Executado em 3 ambientes (dependências conflitantes entre backends pySigma):
  sys    : pySigma 2.x  → Splunk SPL (splunk_windows_pipeline)
  kusto  : pySigma 1.5  → Defender XDR KQL, Elastic Lucene/EQL/ES|QL (ecs_windows), OpenSearch Lucene (ecs_windows), Stellar Cyber (Lucene campos nativos)
  qradar : pySigma 0.11 → QRadar AQL (QRadarAQL_fields_pipeline)
Uso: python convert_worker.py <env>   → grava /tmp/build/conv_<env>.json  {rule_id: {fmt: query | {"err": msg}}}"""
import json, sys, warnings, traceback
warnings.filterwarnings("ignore")
from sigma.collection import SigmaCollection
env = sys.argv[1]
IDX = json.load(open("/tmp/build/rules_index.json"))["rules"]

def mk():
    if env == "sys":
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline
        from sigma.pipelines.sysmon import sysmon_pipeline
        return {"splunk": [lambda: SplunkBackend(processing_pipeline=sysmon_pipeline() + splunk_windows_pipeline()),
                           lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline()), lambda: SplunkBackend()]}
    if env == "kusto":
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        from sigma.backends.elasticsearch import LuceneBackend, EqlBackend, ESQLBackend
        from sigma.backends.opensearch import OpensearchLuceneBackend
        from sigma.pipelines.elasticsearch.windows import ecs_windows
        return {"defender": [lambda: KustoBackend(processing_pipeline=microsoft_xdr_pipeline())],
                "elastic": [lambda: LuceneBackend(processing_pipeline=ecs_windows())],
                "eql": [lambda: EqlBackend(processing_pipeline=ecs_windows())],
                "esql": [lambda: ESQLBackend(processing_pipeline=ecs_windows())],
                "opensearch": [lambda: OpensearchLuceneBackend(processing_pipeline=ecs_windows())],
                "stellar": [lambda: LuceneBackend()]}
    if env == "qradar":
        from sigma.backends.QRadarAQL import QRadarAQLBackend
        from sigma.pipelines.QRadarAQL import QRadarAQL_fields_pipeline, QRadarAQL_payload_pipeline
        return {"qradar": [lambda: QRadarAQLBackend(processing_pipeline=QRadarAQL_fields_pipeline()),
                           lambda: QRadarAQLBackend(processing_pipeline=QRadarAQL_payload_pipeline())]}

B = mk()
out = {}
for rid, r in IDX.items():
    y = open(r["path"], encoding="utf-8").read()
    res = {}
    for fmt, factories in B.items():
        err = None
        for k, fac in enumerate(factories):
            try:
                q = fac().convert(SigmaCollection.from_yaml(y))
                q = "\n".join(x if isinstance(x, str) else json.dumps(x) for x in q)
                if not q.strip(): raise ValueError("saída vazia")
                NOTE = {"splunk": ["", "pipeline splunk_windows (sem mapeamento Sysmon EventID)", "sem pipeline: campos Sigma nativos – ajuste index/sourcetype"],
                        "qradar": ["", "fallback QRadarAQL_payload_pipeline: campos sem propriedade DSM mapeada são buscados em UTF8(payload) – custo maior, crie custom properties"]}
                res[fmt] = q if k == 0 else {"q": q, "note": NOTE.get(fmt, ["", "fallback"] * 2)[k]}
                err = None
                break
            except Exception as ex:
                err = f"{type(ex).__name__}: {str(ex).splitlines()[0][:220] if str(ex) else ''}"
        if err: res[fmt] = {"err": err}
    out[rid] = res
json.dump(out, open(f"/tmp/build/conv_{env}.json", "w"))
ok = {f: sum(1 for v in out.values() if isinstance(v.get(f), str)) for f in B}
print(env, "regras:", len(out), "ok por formato:", ok)
