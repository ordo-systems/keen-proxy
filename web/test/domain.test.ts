import { test } from 'node:test'
import assert from 'node:assert/strict'
import { domainName } from '../src/domain.ts'
test('canonical DNS lookup names follow model entries including IDNA and comments', () => {
  assert.equal(domainName('*.\u041f\u0440\u0438\u043c\u0435\u0440.\u0420\u0424. # comment'), 'xn--e1afmkfd.xn--p1ai')
  assert.equal(domainName('EXAMPLE.com # note'), 'example.com')
  assert.equal(domainName('203.0.113.1 # static address'), null)
  assert.equal(domainName('203.0.113.0/24'), null)
  assert.equal(domainName('010.0.0.1'), '010.0.0.1')
  assert.equal(domainName('10.0.0.1/32'), null)
  assert.equal(domainName('::ffff:10.0.0.1'), null)
})
