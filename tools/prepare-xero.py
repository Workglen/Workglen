#!/usr/bin/env python3
"""Build an offline Xero cutover bundle from complete native API JSON exports.
No network access or token handling. Review the output before importing it.
"""
import argparse,json,pathlib
p=argparse.ArgumentParser(description=__doc__)
for k in ('accounts','contacts','invoices','credit-notes','prepayments','overpayments','trial-balance','source-org','as-of','currency','receivable-account','payable-account','output'):p.add_argument('--'+k,required=True)
p.add_argument('--source-frozen',action='store_true',required=True)
a=p.parse_args()
b=dict(source_org=a.source_org,as_of=a.as_of,currency=a.currency,receivable_account=a.receivable_account,payable_account=a.payable_account,source_frozen=a.source_frozen,trial_balance_csv=pathlib.Path(a.trial_balance).read_text(encoding='utf-8-sig'))
for key,wrapper in [('accounts','Accounts'),('contacts','Contacts'),('invoices','Invoices'),('credit_notes','CreditNotes'),('prepayments','Prepayments'),('overpayments','Overpayments')]:
    # Preserve decimal JSON numbers exactly by parsing them as strings.
    v=json.loads(pathlib.Path(getattr(a,key)).read_text(),parse_float=str)
    if isinstance(v,dict):v=v.get(wrapper)
    if not isinstance(v,list):p.error(f'{key}: expected an array or {wrapper} array')
    b[key]=v
with pathlib.Path(a.output).open('x') as f:json.dump(b,f,indent=2);f.write('\n')
print('Prepared bundle. Validate and review it in Workglen before committing.')
