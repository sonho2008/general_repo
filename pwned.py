
import hashlib, argparse
import urllib3, certifi

def result_parsed(data):
  lines = data.split('\r\n')
  return [l.split(':')  for l in lines]

def main(pw=None, hash=None):
  #
  url_template = 'https://api.pwnedpasswords.com/range/{}'

  # hash of password:
  if hash is None:
    hash = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()

  # first 5 characters of hashed password:
  hash5 = hash[:5]

  # send hash5 to the API securely:
  pm = urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
      ca_certs=certifi.where())
  r = pm.request('GET', url_template.format(hash5))
  assert r.status == 200

  # Parse result
  result = result_parsed(r.data.decode('utf-8'))

  # Try to match original hash
  pwned = False
  for tail, count in result:
    if hash == hash5 + tail:
      pwned = True
      print('hash: {}'.format(hash))
      print('Pwned {} times'.format(count))
      break
  if not pwned:
    print('Not pwned')

if __name__ == '__main__':
  _parser = argparse.ArgumentParser()
  _parser.add_argument('--pw', help='password', type=str, default='password1')
  _parser.add_argument('--hash', help='hash', type=str)
  args = _parser.parse_args()
  main(args.pw, hash=args.hash)
