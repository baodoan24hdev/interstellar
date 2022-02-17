#!/usr/bin/env node
// Temporary demo client
// Works both in browser and node.js

require('dotenv').config()
const assert = require('assert')
const snarkjs = require('snarkjs')
const crypto = require('crypto')
const circomlib = require('circomlib')
const bigInt = snarkjs.bigInt
const merkleTree = require('./lib/MerkleTree')
const Web3 = require('web3')
const buildGroth16 = require('websnark/src/groth16')
const websnarkUtils = require('websnark/src/utils')
const { toWei, toBN, BN } = require('web3-utils')
const config = require('./config')

const userBalance = document.getElementById('userBalance')
const inputNoteString = document.getElementById('inputNoteString')
const noteText = document.getElementById('noteText')
const loginButton = document.getElementById('loginButton')
const userWallet = document.getElementById('userWallet')
const alertLabel = document.getElementById('alert')
const recipientAddress = document.getElementById('recipientAddress')
let depositModal = new bootstrap.Modal(document.getElementById('depositModal'), {})
let withdrawModal = new bootstrap.Modal(document.getElementById('withdrawModal'), {})

let web3, inter, interContract, interInstance, circuit, proving_key, groth16, senderAccount, netId
let MERKLE_TREE_HEIGHT, ETH_AMOUNT

/** Browser or node.js */
const inBrowser = typeof window !== 'undefined'
let isLocalRPC = false

/** Generate random number of specified byte length */
const rbigint = (nbytes) => snarkjs.bigInt.leBuff2int(crypto.randomBytes(nbytes))

/** Compute pedersen hash */
const pedersenHash = (data) => circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0]

/** BigNumber to hex string of specified length */
function toHex(number, length = 32) {
  const str = number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)
  return '0x' + str.padStart(length * 2, '0')
}

/** Display ETH account balance */
async function printETHBalance({ address, name }) {
  console.log(`${name} ETH balance is`, web3.utils.fromWei(await web3.eth.getBalance(address)))
}

/**
 * Create deposit object from secret and nullifier
 */
function createDeposit({ nullifier, secret }) {
  const deposit = { nullifier, secret }
  deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)])
  deposit.commitment = pedersenHash(deposit.preimage)
  deposit.commitmentHex = toHex(deposit.commitment)
  deposit.nullifierHash = pedersenHash(deposit.nullifier.leInt2Buff(31))
  deposit.nullifierHex = toHex(deposit.nullifierHash)
  return deposit
}

/**
 * Make a deposit
 * @param currency Сurrency
 * @param amount Deposit amount
 */
async function deposit({ currency, amount }) {
  const deposit = createDeposit({
    nullifier: rbigint(31),
    secret: rbigint(31)
  })
  const note = toHex(deposit.preimage, 62)
  const noteString = `interstellar-${currency}-${amount}-${netId}-${note}`
  console.log(`Your note: ${noteString}`)
  depositModal.show()
  noteText.innerText = noteString
  await printETHBalance({ address: inter._address, name: 'Interstellar' })
  await printETHBalance({ address: senderAccount, name: 'Sender account' })
  const value = isLocalRPC ? ETH_AMOUNT : fromDecimals({ amount, decimals: 18 })
  console.log('Submitting deposit transaction')
  await inter.methods.deposit(interInstance, toHex(deposit.commitment), []).send({ value, from: senderAccount, gas: 2e6 })
  await printETHBalance({ address: inter._address, name: 'Interstellar' })
  await printETHBalance({ address: senderAccount, name: 'Sender account' })

  alertLabel.innerText = 'Withdraw 1 ETH successful!'
  $('#alert').show()

  setTimeout(() => {
    $('#alert').hide()
  }, 5000)

  return noteString
}

/**
 * Generate merkle tree for a deposit.
 * Download deposit events from the interstellar, reconstructs merkle tree, finds our deposit leaf
 * in it and generates merkle proof
 */
async function generateMerkleProof(deposit, amount) {
  let leafIndex = -1
  // Get all deposit events from smart contract and assemble merkle tree from them

  const cachedEvents = loadCachedEvents({ type: 'Deposit', amount })

  const startBlock = cachedEvents.lastBlock

  let rpcEvents = await interContract.getPastEvents('Deposit', {
    fromBlock: startBlock,
    toBlock: 'latest'
  })

  rpcEvents = rpcEvents.map(({ blockNumber, transactionHash, returnValues }) => {
    const { commitment, leafIndex, timestamp } = returnValues
    return {
      blockNumber,
      transactionHash,
      commitment,
      leafIndex: Number(leafIndex),
      timestamp
    }
  })

  const events = cachedEvents.events.concat(rpcEvents)
  console.log('events', events.length)

  const leaves = events
    .sort((a, b) => a.leafIndex - b.leafIndex) // Sort events in chronological order
    .map((e) => {
      const index = toBN(e.leafIndex).toNumber()

      if (toBN(e.commitment).eq(toBN(deposit.commitmentHex))) {
        leafIndex = index
      }
      return toBN(e.commitment).toString(10)
    })
  const tree = new merkleTree(MERKLE_TREE_HEIGHT, leaves)

  // Validate that our data is correct
  const root = await tree.root()
  const isValidRoot = await interContract.methods.isKnownRoot(toHex(root)).call()
  const isSpent = await interContract.methods.isSpent(toHex(deposit.nullifierHash)).call()
  assert(isValidRoot === true, 'Merkle tree is corrupted')
  assert(isSpent === false, 'The note is already spent')
  assert(leafIndex >= 0, 'The deposit is not found in the tree')

  // Compute merkle proof of our commitment
  return tree.path(leafIndex)
}

/**
 * Generate SNARK proof for withdrawal
 * @param deposit Deposit object
 * @param recipient Funds recipient
 * @param relayer Relayer address
 * @param fee Relayer fee
 * @param refund Receive ether for exchanged tokens
 */
async function generateProof({ deposit, amount, recipient, relayerAddress = 0, fee = 0, refund = 0 }) {
  // Compute merkle proof of our commitment
  const { root, path_elements, path_index } = await generateMerkleProof(deposit, amount)

  // Prepare circuit input
  const input = {
    // Public snark inputs
    root: root,
    nullifierHash: deposit.nullifierHash,
    recipient: bigInt(recipient),
    relayer: bigInt(relayerAddress),
    fee: bigInt(fee),
    refund: bigInt(refund),

    // Private snark inputs
    nullifier: deposit.nullifier,
    secret: deposit.secret,
    pathElements: path_elements,
    pathIndices: path_index
  }

  console.log('Generating SNARK proof')
  console.time('Proof time')
  const proofData = await websnarkUtils.genWitnessAndProve(groth16, input, circuit, proving_key)
  const { proof } = websnarkUtils.toSolidityInput(proofData)
  console.timeEnd('Proof time')

  const args = [
    toHex(input.root),
    toHex(input.nullifierHash),
    toHex(input.recipient, 20),
    toHex(input.relayer, 20),
    toHex(input.fee),
    toHex(input.refund)
  ]

  return { proof, args }
}

/**
 * Do an ETH withdrawal
 * @param noteString Note to withdraw
 * @param recipient Recipient address
 */
async function withdraw({ deposit, currency, recipient, refund = '0' }) {
  if (currency === 'eth' && refund !== '0') {
    throw new Error('The ETH purchase is supposted to be 0 for ETH withdrawals')
  }
  refund = toWei(refund)
  // using private key
  const { proof, args } = await generateProof({ deposit, recipient, refund })

  console.log('Submitting withdraw transaction')
  let txHashString
  await inter.methods
    .withdraw(interInstance, proof, ...args)
    .send({ from: senderAccount, value: refund.toString(), gas: 1e6 })
    .on('transactionHash', function (txHash) {
      console.log(`The transaction hash is http://localhost:3000/transaction/${txHash}`)
      txHashString = txHash
    })
    .on('error', function (e) {
      console.error('on transactionHash error', e.message)
    })
  console.log('Done')
  alertLabel.innerHTML = `The transaction hash is <a href='http://localhost:3000/transaction/${txHashString}'>https://goerli.etherscan.io/tx/${txHashString}<a/>`
  setTimeout(() => {
    $('#alert').show()
  }, 25000)
}

function fromDecimals({ amount, decimals }) {
  amount = amount.toString()
  let ether = amount.toString()
  const base = new BN('10').pow(new BN(decimals))
  const baseLength = base.toString(10).length - 1 || 1

  const negative = ether.substring(0, 1) === '-'
  if (negative) {
    ether = ether.substring(1)
  }

  if (ether === '.') {
    throw new Error('[ethjs-unit] while converting number ' + amount + ' to wei, invalid value')
  }

  // Split it into a whole and fractional part
  const comps = ether.split('.')
  if (comps.length > 2) {
    throw new Error('[ethjs-unit] while converting number ' + amount + ' to wei,  too many decimal points')
  }

  let whole = comps[0]
  let fraction = comps[1]

  if (!whole) {
    whole = '0'
  }
  if (!fraction) {
    fraction = '0'
  }
  if (fraction.length > baseLength) {
    throw new Error('[ethjs-unit] while converting number ' + amount + ' to wei, too many decimal places')
  }

  while (fraction.length < baseLength) {
    fraction += '0'
  }

  whole = new BN(whole)
  fraction = new BN(fraction)
  let wei = whole.mul(base).add(fraction)

  if (negative) {
    wei = wei.mul(negative)
  }

  return new BN(wei.toString(10), 10)
}

/**
 * Waits for transaction to be mined
 * @param txHash Hash of transaction
 * @param attempts
 * @param delay
 */

function loadCachedEvents({ type, amount }) {
  try {
    if (netId !== 1) {
      return {
        events: [],
        lastBlock: 0
      }
    }

    const module = require(`./cache/${type.toLowerCase()}s_eth_${amount}.json`)

    if (module) {
      const events = module

      return {
        events,
        lastBlock: events[events.length - 1].blockNumber
      }
    }
  } catch (err) {
    throw new Error(`Method loadCachedEvents has error: ${err.message}`)
  }
}

/**
 * Parses interstellar.cash note
 */
function parseNote(noteString) {
  const noteRegex = /interstellar-(?<currency>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/g
  const match = noteRegex.exec(noteString)
  if (!match) {
    throw new Error('The note has invalid format')
  }

  const buf = Buffer.from(match.groups.note, 'hex')
  const nullifier = bigInt.leBuff2int(buf.slice(0, 31))
  const secret = bigInt.leBuff2int(buf.slice(31, 62))
  const deposit = createDeposit({ nullifier, secret })
  const netId = Number(match.groups.netId)

  return {
    currency: match.groups.currency,
    amount: match.groups.amount,
    netId,
    deposit
  }
}

/**
 * Init web3, contracts, and snark
 */
async function init({ noteNetId, currency = 'dai', amount = '100' }) {
  let contractJson, instanceJson, erc20interJson, interAddress
  // TODO do we need this? should it work in browser really?
  if (inBrowser) {
    // Initialize using injected web3 (Metamask)
    // To assemble web version run `npm run browserify`
    web3 = new Web3(window['ethereum'], null, {
      transactionConfirmationBlocks: 1
    })
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' })
    contractJson = await (await fetch('build/contracts/TornadoProxy.abi.json')).json()
    instanceJson = await (await fetch('build/contracts/Instance.abi.json')).json()
    circuit = await (await fetch('build/circuits/tornado.json')).json()
    proving_key = await (await fetch('build/circuits/tornadoProvingKey.bin')).arrayBuffer()
    MERKLE_TREE_HEIGHT = 20
    ETH_AMOUNT = 1e18
    senderAccount = accounts[0]
    window.userWalletAddress = accounts[0]
    userBalance.innerText = web3.utils.fromWei(await web3.eth.getBalance(senderAccount))
  }
  // groth16 initialises a lot of Promises that will never be resolved, that's why we need to use process.exit to terminate the CLI
  groth16 = await buildGroth16()
  netId = await web3.eth.net.getId()
  if (noteNetId && Number(noteNetId) !== netId) {
    throw new Error('This note is for a different network. Specify the --rpc option explicitly')
  }
  isLocalRPC = netId > 42

  if (isLocalRPC) {
    interAddress = currency === 'eth' ? contractJson.networks[netId].address : erc20interJson.networks[netId].address
    senderAccount = (await web3.eth.getAccounts())[0]
  } else {
    try {
      interAddress = config.deployments[`netId${netId}`].proxy
      interInstance = config.deployments[`netId${netId}`][currency].instanceAddress[amount]

      if (!interAddress) {
        throw new Error()
      }
    } catch (e) {
      console.error('There is no such inter instance, check the currency and amount you provide')
      process.exit(1)
    }
  }
  inter = new web3.eth.Contract(contractJson, interAddress)
  interContract = new web3.eth.Contract(instanceJson, interInstance)
}

async function loginWithMetaMask() {
  await init({ currency: 'eth', amount: '1' })
  userWallet.innerText = window.userWalletAddress
  loginButton.innerText = 'Sign out of MetaMask'

  loginButton.removeEventListener('click', loginWithMetaMask)
  $('#depositBtn').prop('disabled', false)
  $('#withdrawBtn').prop('disabled', false)

  setTimeout(() => {
    loginButton.addEventListener('click', signOutOfMetaMask)
  }, 200)
}

function signOutOfMetaMask() {
  window.userWalletAddress = null
  userWallet.innerText = ''
  loginButton.innerText = 'Connect to Wallet'

  loginButton.removeEventListener('click', signOutOfMetaMask)
  $('#depositBtn').prop('disabled', true)
  $('#withdrawBtn').prop('disabled', true)

  setTimeout(() => {
    loginButton.addEventListener('click', loginWithMetaMask)
  }, 200)
}

function toggleButton() {
  if (!window.ethereum) {
    loginButton.innerText = 'MetaMask is not installed'
    loginButton.classList.remove('bg-purple-500', 'text-white')
    loginButton.classList.add('bg-gray-500', 'text-gray-100', 'cursor-not-allowed')
    return false
  }

  loginButton.addEventListener('click', loginWithMetaMask)
}

function main() {
  if (inBrowser) {
    const instance = { currency: 'eth', amount: '1' }
    window.deposit = async () => {
      await deposit(instance)
    }
    window.withdraw = async () => {
      // const noteString = prompt('Enter the note to withdraw')
      // const recipient = prompt('Enter the address to withdraw')
      // const recipient = (await web3.eth.getAccounts())[0]
      const noteString = inputNoteString.value
      const recipient = recipientAddress.value
      withdrawModal.hide()

      const { currency, amount, netId, deposit } = parseNote(noteString)
      await init({ noteNetId: netId, currency, amount })
      await withdraw({ deposit, currency, amount, recipient })
    }
  } else {
    console.log('Please deploy in browser')
  }
}

window.addEventListener('DOMContentLoaded', () => {
  toggleButton()
})

main()
