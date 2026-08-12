import sys
sys.path.insert(0, '.')
from iacp_protocol import *

print("=== PSS Debug ===")
a = IACPAgent('A'); b = IACPAgent('B')
a.start(); b.start()

pss = a.pss_manager
init = pss.initiate_pss(a.eid, b.eid, a.private_key, False)
print('init signature len:', len(init['signature']))

neg = pss.process_pss_init(init, b.eid, b.private_key)
print('neg result:', neg)

if neg is None:
    print('=> process_pss_init returned None, checking signature...')
    ic = bytes.fromhex(init['i_cookie'])
    ie = bytes.fromhex(init['initiator_eid'])
    sig = bytes.fromhex(init['signature'])
    print('ie len:', len(ie), 'ic len:', len(ic), 'sig len:', len(sig))
    print('verify:', verify_signature(ie, ic, sig))
else:
    print('SUCCESS - neg generated')