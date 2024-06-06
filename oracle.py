#!/usr/bin/env python3

from sys import argv, stdin, stderr, exit
from functools import partial
import re

class Goal:
  def __init__(self, goal, vars={}):
    if isinstance(goal, Goal):
      self.num = goal.num
      self.goal = goal.goal
    else:
      (num, goal) = goal.split(':')
      self.num = int(num)
      self.goal = goal.strip()
    self.matched_vars = vars

  def __repr__(self):
    return self.goal

  def __str__(self):
    return str(self.num)

  def __dict__(self):
    return self.matched_vars

GOALS = list(map(Goal, stdin.readlines()))
if not GOALS:
  exit(0)

class Token:
  def __init__(self, raw_token, post_process=None, complement=False, max=3):
    if isinstance(raw_token, re.Pattern):
      self.compiled = raw_token
      self.raw = raw_token.pattern
    else:
      self.compiled = None
      self.raw = raw_token
    self.post_process = None
    self.max = max
    self.complement = complement

  def __eq__(self, val):
    return self.raw == val.raw

  def format(self, goal):
    t = self.raw.format(**goal.matched_vars)
    return Token(t if self.compiled is None else r(t), complement=self.complement, max=self.max)

  def match(self, goal):
    m = (self.raw in repr(goal)) \
        if self.compiled is None \
        else self.compiled.search(repr(goal))

    if callable(self.post_process):
      m = self.post_process(repr(goal), m)

    if bool(m) == self.complement:
      return None
    else:
      vars = m.groupdict() if isinstance(m, re.Match) else {}
      return Goal(goal, { k: re.escape(v) for k, v in vars.items() })

  def match_all(self, goals):
    matches = 0
    for goal in goals:
      m = self.match(goal)
      if m is not None:
        yield m
        matches += 1
      if matches >= self.max and not self.max < 0:
        break

def when_then(when, then, also=None, also_neg=False):
  def yielder(goals=GOALS):
    for when_match in when.match_all(goals):
      if also is not None:
        try:
          next(also.format(when_match).match_all(goals))
          if also_neg:
            continue
        except StopIteration:
          if not also_neg:
            continue

      for match in then.format(when_match).match_all(goals):
        yield match

  return yielder

def match_unless(then, unless):
  def yielder(goals=GOALS):
    for then_match in then.match_all(goals):
      try:
        next(unless.format(then_match).match_all(goals))
        pass
      except StopIteration:
        yield then_match

  return yielder

COMPILE_CACHE = {}

def r(s):
  return COMPILE_CACHE.setdefault(s, re.compile(s))

def prioritize(tokens, goals=GOALS):
  for token in tokens:
    if callable(token):
      for goal in token(goals):
        yield goal
    else:
      t = token if isinstance(token, Token) else Token(token)
      for goal in t.match_all(goals):
        yield goal

def compose(*filters, goals=GOALS):
  gs = goals
  for filter in filters:
    gs = list(filter(goals=gs))
  return gs

match = lambda goals=None: []
if argv[1] == 'Auto_ECDHSkOrigin':
  match = partial(prioritize, [
    'ECDHKeyGen( id, me, them, myPk ) @ #x',
    '@ #t',
    r(r'Session\(.+▶. #t$'),
    r(r'^\(∃'),
    r(r'^ECDHKeyGen'),
  ])
elif argv[1] == 'CkCompromise':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      r(r'!KU\( prefix\(hkdf\(.+\'chain_key\'[\s\)]*@ #\w+(\.\d+)?$'),
      r(r'^\(*last'),
      r(r'RevealChainKey\( \$Me,.+= chainKey.+RevealChainKey\( \$Them,.+chainKey'),
      '∀',

      when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),
      match_unless(
        Token(r(r'^SessionInfo\(.+@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
      ),

      r(r'MessageSent\(.+@ #t1$'),
      r(r'KeysUsed\(.+@ #t1$'),
      r(r'SessionInfo\(.+@ #t1$'),
      r(r'Session.+▶. #t1$'),

      r(r'!KU\( suffix'),
      r(r'!KU\( prefix'),
      r(r'!KU\( hkdf'),
      when_then(
        Token(r(r'Session\(.+hkdf\(chainKey, \'chain_key\'\)\) ▶')),
        Token('PublicKeyRatchet'),
      ),
      r(r'Session\(.+suffix'),
      r(r'Session\(.+▶. #vr\.\d+$'),
      'PublicKeyRatchet',
      'SessionInfo',
    ]),
  )
elif argv[1] == 'Auto_RkSecretCompromiseECDH':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      r(r'!KU\( hkdf\(z, .+\)\^inv\(~ecdhSk\)\s*\) @'),
      r(r'Session\(.+(\'[\w\d_]+\'|>|~kemSS),\s*[\w\d\.\(\)]+\s*\)\s*▶'),
      r(r'Session\(.+hkdf\(hkdf\(ecdhSS, (\'0\'|rootKey)\), \'chain_key\'\)\)\s*▶'),
      r(r'Session\(.+hkdf\(ecdhSS, (\'0\'|rootKey)\)\)\s*▶'),

      r(r'!KU\( prefix\(hkdf\(.+\'chain_key\'[\s\)]*@ #\w+(\.\d+)?$'),
      r(r'^\(*last'),
      '∀',
      r(r'^\(*last'),
      when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),
      match_unless(
        Token(r(r'^SessionInfo\(.*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
      ),

      r(r'MessageSent\(.+@ #t1$'),
      r(r'KeysUsed\(.+@ #t1$'),
      r(r'SessionInfo\(.+@ #t1$'),
      r(r'!KU\(.+@ #t2$'),

      r(r'Session\(.+suffix'),

      r(r'^!KU\( suffix'),
      r(r'^!KU\( hkdf\((ecdhSS|hkdf\(|\'g\'\^)'),

      'PublicKeyRatchet',
      Token('SessionInfo', max=-1),
    ]),
  )
elif argv[1] == 'Auto_RkSecretCompromiseKemSS':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      r(r'\(∃ #x\. \(!KU\( ~?kemSS \) @ #x\).+\$Me'),
      r(r'!KU\( (Just\()?encap\((\'[\w_]+\'|<)'),
      r(r'Session\(.+(\'[\w\d_]+\'|>|~kemSS),\s*[\w\d\.\(\)]+\s*\)\s*▶'),

      r(r'!KU\( prefix\(hkdf\(.+\'chain_key\'[\s\)]*@ #\w+(\.\d+)?$'),
      r(r'^\(*last'),
      when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),
      match_unless(
        Token(r(r'^SessionInfo\(.*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
      ),

      r(r'KeysUsed\(.+@ #t1$'),
      r(r'SessionInfo\(.+@ #t1$'),
      r(r'Session.+▶. #t1$'),
      r(r'!KU\(.+@ #t2$'),

      r(r'^!KU\( suffix\('),
      r(r'^!KU\( hkdf\((hkdf\(|ecdhSS)'),
      r(r'Session\(.+suffix'),
      when_then(
        Token('KU( prefix(t) )'),
        Token('PublicKeyRatchet')
      ),
      '!KU( prefix',
      r(r'Session.+▶. #x'),
      'PublicKeyRatchet',
      r(r'Session.+▶. #vr'),

      'SessionInfo',
    ]),
  )
elif argv[1] == 'CkCompromiseFull':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      '∀',
      r(r'^\(∃ #\w+(\.\d+)?\.\s*\(PQAttack'),
      Token(r(r'\(∃ #\w(\.\d+)?\.\s*\(CompromisedECDH\w+\(')),
      Token(r(r'\(∃ #\w(\.\d+)?\.\s*\(CompromisedKemKey\(')),
      Token(r(r'\(∃ \w+ #\w(\.\d+)?\.\s*\(CompromisedChainKey\(')),

      r(r'SessionInfo\(.+@ #t\d$'),
      r(r'SessionSecrets\(.+@ #t\d$'),
    ]),
  )
elif argv[1] == 'Auto_MkCompromise':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      r(r'^\(*last'),
      '∀',
      when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),
      match_unless(
        Token(r(r'^SessionInfo\(.*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
      ),

      r(r'MessageSent\(.+@ #t\d$'),
      r(r'SessionSecrets\(.+@ #t\d$'),
      r(r'!KU\(.+@ #t2$'),

      r(r'Session\(.+suffix'),
      r(r'^PublicKeyRatchet.+@ #x'),
      'SessionInfo',
    ]),
  )
elif argv[1] == 'Auto_Secrecy':
  match = partial(compose,
    # Filter out where the adversary knows the message key indicator from; this
    # is public and does nothing.
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), max=-1, complement=True).match_all,
    partial(prioritize, [
      '∀',
      r(r'MessageSent\(.+@ #t$'),
      r(r'SessionSecrets\(.+@ #t$'),
      '!KU( ~msg )',
      'PQAttack',
      'RevealECDHKey',
      'RevealKemKey',
      r(r'Reveal(Chain|Message)Key\('),
    ]),
  )
elif argv[1] in ['Auto_RootKeyConnectionSend', 'Auto_RootKeyConnectionReceive']:
  match = partial(prioritize, [
    r(r'^\(?last'),
    'MessageSent',
    'MessageReceived',
    'SymmetricRatchet',
    'KeysUsed',
    'splitEqs',
    'Session(',
  ])
elif argv[1] in ['Auto_RootKeyMonotonicity', 'Auto_RootKeyConnectionInjectivity']:
  match = partial(prioritize, [
    r(r'^\(?last'),
    'last',
    r(r'KeysUsed.+@ #t1$'),
    r(r'SymmetricRatchet.+@ #t1$'),
    r(r'KeysUsed.+@ #t(2|3)$'),
    r(r'SymmetricRatchet.+@ #t(1|2|3)$'),
    r(r'PublicKeyRatchet.+@ #t(1|2|3)$'),
    r(r'SessionInfo.+@ #t(1|2|3)$'),
    r(r'#t\d = #vr(\.\d+)?'),
    r(r'#vr(\.\d+)? = #t\d'),
    r(r'Session\(.+(@|▶.) #t1$'),
    r(r'Session\(.+(@|▶.) #t(2|3)$'),
    r(r'^\(?prefix'),
    'splitEqs',
  ])
elif argv[1] == 'RkFixesKEMSS':
  match = partial(prioritize, [
    r(r'^\(?last'),
    'last',
    r(r'~?kemSS\d?(\.\d)? = ~?kemSS\d?(\.\d)?'),
    when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
    match_unless(
      Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
      Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
    ),
    match_unless(
      Token(r(r'^SessionInfo\(.+@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
      Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
    ),
    r(r'KeysUsed.+@ #t\d$'),
    r(r'SessionInfo.+@ #t\d$'),
    r(r'Session\(.+▶. #t\d$'),
    r(r'Session\(.+▶. #x'),
    r(r'Session\(.+prefix.+▶. #vr$'),
    r(r'PublicKeyRatchet.+@ #x\.(1|3)$'),
    r(r'Session\(.+prefix'),
    'Session(',
    'PublicKeyRatchet',
    r(r'^(Decap|New)KemSS'),
    r(r'(Decap|New)KemSS'),
  ])
elif argv[1] == 'Auto_RkFixesEcdhSS':
  match = partial(prioritize, [
    r(r'^\(?last'),
    'last',
    r(r'~?ecdhSS\d?(\.\d)? = ~?ecdhSS\d?(\.\d)?'),
    r(r'KeysUsed.+@ #t\d$'),
    r(r'PublicKeyRatchet.+prefix\(hkdf'),
    r(r'SessionInfo.+@ #t\d$'),
    r(r'Session\(.+▶. #t\d$'),
    r(r'PublicKeyRatchet.+@ #x\.(1|2)$'),
  ])
elif argv[1].startswith('Auto_ChainKeyMonotonicity'):
  match = partial(prioritize, [
    'KeysUsed',
    'Session(',
  ])
elif argv[1] == 'Auto_ECDHSSCompromise':
  match = partial(compose,
    Token(r(r'!KU\( hkdf.+\'msg_key_ind\''), complement=True, max=-1).match_all,
    partial(prioritize, [
      '!KU( ~idKey',
      'IDSQuery',
      match_unless(
        Token(r(r'!KU\( (?P<sk>~ecdhSk(\.\d)?) \)')),
        Token(r(r'ECDH(Pre)?Key(Gen)?.+{sk} \)')),
      ),
      when_then(
        Token(r(r'!KU\( (?P<sk>~ecdhSk(\.\d)?) \)')),
        Token(r(r'!ECDHPreKey.+{sk} \)')),
      ),
      when_then(
        Token(r(r'!KU\( (?P<sk>~ecdhSk(\.\d)?) \)')),
        Token(r(r'^ECDH(Pre)?KeyGen.+{sk} \)')),
      ),
      when_then(
        Token(r(r'!KU\( (?P<sk>~ecdhSk(\.\d)?) \)')),
        Token(r(r'ECDH(Pre)?KeyGen.+{sk} \)')),
      ),
      '!KU( ~preKey',
      r(r'!KU\( \'g\'\^\([~\w\d\.]+\*[~\w\d\.]+\)'),

      # Solve for lemma premise
      '@ #t1',

      when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),
      match_unless(
        Token(r(r'^SessionInfo\(.*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^(PublicKeyRatchet|SessionStart).+@ {tvar}$')),
      ),
      r(r'SessionStart\( (pk\(x\)|theirIdPk) \)'),
      r(r'^PublicKeyRatchet.+@ #x\.1$'),
      r(r'ECDH(Pre)?KeyGen\(.+\'g\'\^~ecdhSk \)'),
      'IDSQuery',

      # Solve for protocol flow
      r(r'Session\(.+\) ▶. #x$'),
      r(r'!KU\( sign.+None>,\s*~idKey'),
      '!KU( sign',
      match_unless(
        Token(r(r'Session\(.+\) ▶. #t1$')),
        Token('PublicKeyRatchet'),
      ),
      r(r'NewECDHSS.+@ #x$'),
      'PublicKeyRatchet( ~id, $Them, $Me',
    ])
  )
elif argv[1] == 'Auto_MyKemKeyOrigin':
  match = partial(prioritize, [
    r(r'^\(last'),
    r(r'KeysUsed\(.+\) @ #t$'),
    r(r'SessionInfo\(.+\) @ #t$'),
    'NewKemKey',
    r(r'^KemKeyGen'),
    'last',
    '!KemPreKey',
    'Session(',
  ])
elif argv[1] == 'Auto_MaybeNewKemKeyOrigin':
  match = partial(prioritize, [
    'last',
    r(r'KeysUsed\(.+\) @ #t\b'),
    r(r'SessionInfo\(.+\) @ #t\b'),
    '!KemPreKey',
    'NewKemPublicKey',
    'Session(',
  ])
elif argv[1] == 'Auto_TheirKemKeyOrigin':
  match = partial(prioritize, [
    'last',
    r(r'KeysUsed\(.+\) @ #t\b'),
    r(r'SessionInfo\(.+\) @ #t\b'),
    r(r'Session\(.+\) ▶. #t\b'),
    'NewKemPublicKey',
    'Session(',
  ])
elif argv[1] in ['Auto_KemKeyOriginEncap', 'Auto_KemKeyOriginDecap']:
  match = partial(prioritize, [
    r(r'@ #t$'),
    r(r'∃.+KemKeyGen'),
  ])
elif argv[1] == 'Auto_KemSSOrigin':
  match = partial(prioritize, [
    when_then(
      Token(r(r'SessionInfo\(.+\) @ #t$')),
      Token(r(r'^\(#\w(\.\d+)? < #t')),
    ),
    r(r'^\(last\(#t\)\)'),
    r(r'KeysUsed\(.+\) @ #t$'),
    r(r'SessionInfo\(.+\) @ #t$'),
    'last',
    r(r'Session\(.+\) ▶. #t$'),
  ])
elif argv[1] == 'KemSSCompromise':
  match = partial(prioritize, [
    r(r'KeysUsed.+@ #t1$'),
    r(r'SessionInfo.+@ #t1$'),

    'IDSQuery',
    when_then(
      Token(r(r'^SessionStart\( [^~]+ \) @ (?P<t_var>#x(\.\d+)?)')),
      Token(r(r'^SessionInfo\( ~id.+\) @ {t_var}$')),
    ),
    r(r'SessionStart\( [^~]+ \)'),

    '(∃ #x.   (NewKemSS( ~id, $Me, $Them, kemSS, encapPk ) @ #x) ∧ #x < #t1)  ∥ (∃ #x.   (DecapKemSS( ~id, $Me, $Them, kemSS, encapPk ) @ #x) ∧ #x < #t1)',

    '!KU( ~idKey',
    '!KU( ~newKemSk',
    '!KU( ~kemSk',
    '!KU( ~kemPreKey',

    r(r'^NewKemSS'),
    r(r'^DecapKemSS'),
    r(r'^KemKeyGen'),
    r(r'^NewKemPublicKey\(.+, Just\(encapPk\)'),
    r(r'^NewKemKey\(.+Just\(pqpk\(~kemSk'),

    # Match incoming encapsulation keys and encapsulations, but only if they're
    # not from the setup ratchet ('\(%i...'-match) and are sent from by the peer
    # ('<\$Them...' match)
    r(r'^!KU\( sign\(.*, \(%i(\.\d+)?%\+%1\), .*<\$Them, [\w\d\.\(\)~]+, \$Me, [\w\d\.\(\)~]+>, .*Just\(encapPk\)'),
    r(r'^!KU\( sign\(.*, \(%i(\.\d+)?%\+%1\), .*<\$Them, [\w\d\.\(\)~]+, \$Me, [\w\d\.\(\)~]+>, .*Just\(kemEncap(\.\d+)?\)'),
    match_unless(
      Token(r(r'^!KU\( sign\(.*, .*<\$Them, [\w\d\.\(\)~]+, \$Me, [\w\d\.\(\)~]+>, .*Just\(kemEncap(\.\d+)?\)')),
      Token('!KU( Just(encap(~kemSS'),
    ),

    '!KU( ~kemSS',
  ])
elif argv[1] == 'Auto_NoninjectiveAgreement':
  match = partial(prioritize, [
    r(r'!KU\( ~idKey'),
    'IDSQuery',
    match_unless(
      Token(r(r'SessionStart\( pk\(x\) \) @ #x\.1')),
      Token(r(r'SessionInfo\( ~id, %1.+@ #x\.1\b')),
    ),
    when_then(
      Token(r(r'SessionStart\( pk\(x\) \) @ #x\.1')),
      Token(r(r'SessionInfo\( ~id, %1.+@ #x\.1\b')),
    ),
    r(r'!KU\( sign\(.*~idKey'),
  ])
elif argv[1] == 'InjectiveMessageReceived':
  match = partial(prioritize, [
    r(r'^ECDHKeyGen'),
    r(r'!ECDHPreKey'),
    r(r'@ #t(1|2)$'),
    r(r'!KU\( ~idKey'),
    # Token(
    #   r(r'PublicKeyRatchet\(.*\'g\'\^\((?P<kprod1>~ecdhSk(\.\d)?\*~ecdhSk(\.\d)?)\),.*hkdf\(\'g\'\^\((?P<kprod2>~ecdhSk(\.\d)?\*~ecdhSk(\.\d)?)\)'),
    #   post_process=lambda _, m: None if m is None or m['kprod1'] == m['kprod2'] else m,
    # ),

    when_then(
      Token(r(r'SessionStart\( pk\(\w+\) \) @ (?P<tvar>#[\w\d\.]+)')),
      Token(r(r'SessionInfo\(.+\) @ {tvar}\b')),
    ),
    r(r'SessionStart\( pk\(\w+\) \)'),
    'IDSQuery',

    when_then(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^SessionInfo\(.+@ {tvar}$'), max=-1),
        also=Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
        also_neg=True,
      ),
      match_unless(
        Token(r(r'^To(Sender|Receiver)\(\s*\)\s*@ (?P<tvar>#\w+(\.\d+)?)$'), max=-1),
        Token(r(r'^PublicKeyRatchet.+@ {tvar}$')),
      ),

    r(r'^!KU\( sign\(<\'msg_sig\',\s*senc\(~m.*<\$Them(\.\d)?, [\w\d\.\(\)~]+, \$Me(\.\d+)?, [\w\d\.\(\)~]+>'),
    r(r'^!KU\( sign\(.*ciphertext,.*\(%i(\.\d+)?(%\+%1)+\), .*<\$Them(\.\d)?, [\w\d\.\(\)~]+, \$Me(\.\d+)?, [\w\d\.\(\)~]+>'),

    r(r'ECDHKeyGen'),

    r(r'Session\(.+\) ▶. #t1$'),
    r(r'^!KU\( sign\(.*ciphertext,.*<\$Them(\.\d)?, [\w\d\.\(\)~]+, \$Me(\.\d+)?, [\w\d\.\(\)~]+>'),
  ])
elif argv[1] in ['Auto_MkCkRelation', 'Auto_CkRkRelation']:
  match = partial(prioritize, [
    'last',
    r(r'KeysUsed\(.+(@|▶.) #t\d'),
    r(r'SessionInfo.+(@|▶.) #t\d'),
    '$Me = $Me.1',
    r(r'Session\(.+(@|▶.) #t\d'),
    r(r'~id(\.\d)? = ~id(\.\d)?'),
    'PublicKeyRatchet',
    'ToSender',
    'ToReceiver',
    r(r'SessionInfo\(.+@ #x(\.1)?$'),
    'splitEqs(1)',
    'splitEqs(0)',
    'splitEqs',
  ])
elif argv[1] == 'Auto_ChainKeySources':
  match = partial(prioritize, [
    r(r'Session\(.+(@|▶.) #vr'),
  ])
elif argv[1].startswith('ChainKeyFormat'):
  match = partial(prioritize, [
    'Session',
  ])
elif argv[1] == 'Auto_SessionStart':
  match = partial(prioritize, [
    'last',
    r(r'@ #t$'),
    r(r'Session\(.+ ▶. #t$'),
  ])
elif argv[1] == 'Auto_SessionStartUnique':
  match = partial(prioritize, [
    'SessionInfo',
  ])
elif argv[1] in ['ExecutabilityPublicKeyRatchetSomeNewKEMSS', 'ExecutabilityPublicKeyRatchetNoNewKEMSS']:
  def sortByLen(goals=[]):
    goals.sort(key=lambda g: len(repr(g)), reverse=True)
    return goals

  def preserveIfEmpty(filter, goals=[]):
    matches = list(filter(goals=goals))
    if not matches:
      return goals
    else:
      return matches

  match = partial(compose,
    sortByLen,
    partial(preserveIfEmpty,
      partial(prioritize, [
        'DecapKemSS',
        r(r'@ #t(1|2|3)?$'),
      ])
    ),
  )
elif argv[1] == 'Auto_RkFormat':
  match = partial(prioritize, [
    'last',
    'KeysUsed',
    r(r'Session.+▶. #t$'),
  ])
elif argv[1] == 'Debug':
  match = partial(compose,
    Token('b', complement=True).match_all,
    partial(prioritize, [
      when_then(Token('c'), Token('a')),
      match_unless(Token('c'), Token('b')),
    ])
  )

printed = set()
for goal_num in (map(str, match(goals=GOALS))):
  if goal_num not in printed:
    print(goal_num)
    printed.add(goal_num)
