import express from "express";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { randomBytes } from "crypto";
import {
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

const app = express();
app.use(express.json());

const SYSTEM_PROGRAM_ID = SystemProgram.programId;
const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

const RPC_INVALID_REQUEST = -32600;
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_INVALID_PARAMS = -3;
const RPC_TX_FAILED = -32003;

type LedgerAccount = {
  pubkey: string;
  lamports: bigint;
  owner: string;
  data: Buffer;
  executable: boolean;
  rentEpoch: number;
};

type SignatureStatus = {
  slot: number;
  confirmations: null;
  err: null;
  confirmationStatus: "confirmed";
};

const accounts = new Map<string, LedgerAccount>();
const signatureStatuses = new Map<string, SignatureStatus>();
const issuedBlockhashes = new Map<string, number>();

let slot = 1;
let blockHeight = 1;

function rpcResult(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function toPublicKey(value: unknown): PublicKey {
  if (typeof value !== "string") {
    throw new Error("Expected base58 pubkey string");
  }
  return new PublicKey(value);
}

function toBigIntAmount(value: unknown): bigint {
  if (typeof value !== "number" && typeof value !== "string") {
    throw new Error("Expected numeric amount");
  }
  const v = BigInt(value);
  if (v < 0n) {
    throw new Error("Amount must be non-negative");
  }
  return v;
}

function getOrCreateSystemAccount(pubkey: PublicKey): LedgerAccount {
  const key = pubkey.toBase58();
  const existing = accounts.get(key);
  if (existing) {
    return existing;
  }
  const created: LedgerAccount = {
    pubkey: key,
    lamports: 0n,
    owner: SYSTEM_PROGRAM_ID.toBase58(),
    data: Buffer.alloc(0),
    executable: false,
    rentEpoch: 0,
  };
  accounts.set(key, created);
  return created;
}

function getAccount(pubkey: PublicKey): LedgerAccount | undefined {
  return accounts.get(pubkey.toBase58());
}

function writeU64LE(buf: Buffer, offset: number, value: bigint) {
  buf.writeBigUInt64LE(value, offset);
}

function readU64LE(buf: Buffer, offset: number): bigint {
  return buf.readBigUInt64LE(offset);
}

function toRpcAccountInfo(account: LedgerAccount) {
  return {
    data: [account.data.toString("base64"), "base64"],
    executable: account.executable,
    lamports: Number(account.lamports),
    owner: account.owner,
    rentEpoch: account.rentEpoch,
  };
}

function rentExemptMin(dataSize: number): number {
  return (dataSize + 128) * 2;
}

type NormalizedInstruction = {
  programId: PublicKey;
  keys: Array<{ pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>;
  data: Buffer;
};

type ParsedTransaction = {
  signatures: string[];
  recentBlockhash: string;
  instructions: NormalizedInstruction[];
  signerPubkeys: string[];
  signerSet: Set<string>;
};

function verifyLegacyTransaction(tx: Transaction): ParsedTransaction {
  const messageBytes = tx.serializeMessage();
  const signerPubkeys: string[] = [];
  const signerSet = new Set<string>();

  for (const sig of tx.signatures) {
    const pk = sig.publicKey.toBase58();
    signerPubkeys.push(pk);
    signerSet.add(pk);
    if (!sig.signature || sig.signature.every((b) => b === 0)) {
      throw new Error("Missing signature");
    }
    const ok = nacl.sign.detached.verify(messageBytes, sig.signature, sig.publicKey.toBytes());
    if (!ok) {
      throw new Error("Invalid signature");
    }
  }

  return {
    signatures: tx.signatures.map((s) => bs58.encode(s.signature!)),
    recentBlockhash: tx.recentBlockhash ?? "",
    instructions: tx.instructions.map((ix) => ({
      programId: ix.programId,
      data: Buffer.from(ix.data),
      keys: ix.keys.map((k) => ({ pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable })),
    })),
    signerPubkeys,
    signerSet,
  };
}

function verifyVersionedTransaction(tx: VersionedTransaction): ParsedTransaction {
  const messageBytes = tx.message.serialize();
  const accountKeys = tx.message.getAccountKeys().staticAccountKeys;
  const required = tx.message.header.numRequiredSignatures;
  const signerPubkeys: string[] = [];
  const signerSet = new Set<string>();

  for (let i = 0; i < required; i++) {
    const pubkey = accountKeys[i];
    const sig = tx.signatures[i];
    const pk = pubkey.toBase58();
    signerPubkeys.push(pk);
    signerSet.add(pk);
    if (!sig || sig.every((b) => b === 0)) {
      throw new Error("Missing signature");
    }
    const ok = nacl.sign.detached.verify(messageBytes, sig, pubkey.toBytes());
    if (!ok) {
      throw new Error("Invalid signature");
    }
  }

  const decompiled = TransactionMessage.decompile(tx.message);

  return {
    signatures: tx.signatures.map((s) => bs58.encode(s)),
    recentBlockhash: decompiled.recentBlockhash,
    instructions: decompiled.instructions.map((ix: TransactionInstruction) => ({
      programId: ix.programId,
      data: Buffer.from(ix.data),
      keys: ix.keys.map((k) => ({ pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable })),
    })),
    signerPubkeys,
    signerSet,
  };
}

function parseAndVerifyTransaction(encodedTx: string): ParsedTransaction {
  const raw = Buffer.from(encodedTx, "base64");

  try {
    const tx = Transaction.from(raw);
    return verifyLegacyTransaction(tx);
  } catch {
    const tx = VersionedTransaction.deserialize(raw);
    return verifyVersionedTransaction(tx);
  }
}

function ensureSigner(ix: NormalizedInstruction, signerSet: Set<string>, index: number): string {
  const key = ix.keys[index];
  if (!key) {
    throw new Error("Missing account");
  }
  if (!key.isSigner) {
    throw new Error("Required signer missing");
  }
  const pk = key.pubkey.toBase58();
  if (!signerSet.has(pk)) {
    throw new Error("Instruction signer not present");
  }
  return pk;
}

function executeSystemInstruction(ix: NormalizedInstruction, signerSet: Set<string>) {
  if (ix.data.length < 4) {
    throw new Error("Invalid system instruction data");
  }
  const disc = ix.data.readUInt32LE(0);

  if (disc === 0) {
    if (ix.data.length < 52 || ix.keys.length < 2) {
      throw new Error("Invalid CreateAccount instruction");
    }
    ensureSigner(ix, signerSet, 0);
    ensureSigner(ix, signerSet, 1);
    const lamports = readU64LE(ix.data, 4);
    const space = Number(readU64LE(ix.data, 12));
    const ownerPk = new PublicKey(ix.data.subarray(20, 52));

    const payer = getOrCreateSystemAccount(ix.keys[0].pubkey);
    const newPk = ix.keys[1].pubkey.toBase58();
    const existing = accounts.get(newPk);
    if (existing && (existing.lamports > 0n || existing.data.length > 0)) {
      throw new Error("Account already in use");
    }
    if (payer.lamports < lamports) {
      throw new Error("Insufficient funds");
    }
    payer.lamports -= lamports;
    accounts.set(newPk, {
      pubkey: newPk,
      lamports,
      owner: ownerPk.toBase58(),
      data: Buffer.alloc(space),
      executable: false,
      rentEpoch: 0,
    });
    return;
  }

  if (disc === 2) {
    if (ix.data.length < 12 || ix.keys.length < 2) {
      throw new Error("Invalid Transfer instruction");
    }
    ensureSigner(ix, signerSet, 0);
    const lamports = readU64LE(ix.data, 4);
    const source = getOrCreateSystemAccount(ix.keys[0].pubkey);
    const destination = getOrCreateSystemAccount(ix.keys[1].pubkey);
    if (source.lamports < lamports) {
      throw new Error("Insufficient funds");
    }
    source.lamports -= lamports;
    destination.lamports += lamports;
    return;
  }

  throw new Error(`Unsupported System instruction: ${disc}`);
}

function ensureTokenAccount(account: LedgerAccount | undefined): LedgerAccount {
  if (!account || account.owner !== TOKEN_PROGRAM_ID.toBase58() || account.data.length < 165) {
    throw new Error("Invalid token account");
  }
  return account;
}

function ensureMintAccount(account: LedgerAccount | undefined): LedgerAccount {
  if (!account || account.owner !== TOKEN_PROGRAM_ID.toBase58() || account.data.length < 82) {
    throw new Error("Invalid mint account");
  }
  return account;
}

function tokenAccountMint(account: LedgerAccount): string {
  return new PublicKey(account.data.subarray(0, 32)).toBase58();
}

function tokenAccountOwner(account: LedgerAccount): string {
  return new PublicKey(account.data.subarray(32, 64)).toBase58();
}

function tokenAccountAmount(account: LedgerAccount): bigint {
  return readU64LE(account.data, 64);
}

function setTokenAccountAmount(account: LedgerAccount, value: bigint) {
  writeU64LE(account.data, 64, value);
}

function mintSupply(mint: LedgerAccount): bigint {
  return readU64LE(mint.data, 36);
}

function setMintSupply(mint: LedgerAccount, value: bigint) {
  writeU64LE(mint.data, 36, value);
}

function mintDecimals(mint: LedgerAccount): number {
  return mint.data.readUInt8(44);
}

function executeTokenInstruction(ix: NormalizedInstruction, signerSet: Set<string>) {
  if (ix.data.length < 1) {
    throw new Error("Invalid token instruction data");
  }

  const disc = ix.data.readUInt8(0);

  if (disc === 20) {
    if (ix.keys.length < 1 || ix.data.length < 67) {
      throw new Error("Invalid InitializeMint2 instruction");
    }
    const mint = ensureMintAccount(getAccount(ix.keys[0].pubkey));
    if (mint.data[45] === 1) {
      throw new Error("Mint already initialized");
    }
    const decimals = ix.data.readUInt8(1);
    const mintAuthority = ix.data.subarray(2, 34);
    const hasFreezeAuth = ix.data.readUInt8(34);
    const freezeAuthority = ix.data.subarray(35, 67);

    mint.data.writeUInt32LE(1, 0);
    mintAuthority.copy(mint.data, 4);
    writeU64LE(mint.data, 36, 0n);
    mint.data.writeUInt8(decimals, 44);
    mint.data.writeUInt8(1, 45);
    mint.data.writeUInt32LE(hasFreezeAuth ? 1 : 0, 46);
    if (hasFreezeAuth) {
      freezeAuthority.copy(mint.data, 50);
    } else {
      mint.data.fill(0, 50, 82);
    }
    return;
  }

  if (disc === 18) {
    if (ix.keys.length < 2 || ix.data.length < 33) {
      throw new Error("Invalid InitializeAccount3 instruction");
    }
    const tokenAcc = ensureTokenAccount(getAccount(ix.keys[0].pubkey));
    const mint = ensureMintAccount(getAccount(ix.keys[1].pubkey));
    const owner = ix.data.subarray(1, 33);
    if (tokenAcc.data[108] === 1) {
      throw new Error("Token account already initialized");
    }
    ix.keys[1].pubkey.toBuffer().copy(tokenAcc.data, 0);
    owner.copy(tokenAcc.data, 32);
    writeU64LE(tokenAcc.data, 64, 0n);
    tokenAcc.data.fill(0, 72, 108);
    tokenAcc.data.writeUInt8(1, 108);
    tokenAcc.data.fill(0, 109, 121);
    writeU64LE(tokenAcc.data, 121, 0n);
    tokenAcc.data.fill(0, 129, 165);
    if (mint.data[45] !== 1) {
      throw new Error("Mint not initialized");
    }
    return;
  }

  if (disc === 7) {
    if (ix.keys.length < 3 || ix.data.length < 9) {
      throw new Error("Invalid MintTo instruction");
    }
    const mint = ensureMintAccount(getAccount(ix.keys[0].pubkey));
    const destination = ensureTokenAccount(getAccount(ix.keys[1].pubkey));
    const authorityPk = ensureSigner(ix, signerSet, 2);
    const mintAuthorityOption = mint.data.readUInt32LE(0);
    const mintAuthority = new PublicKey(mint.data.subarray(4, 36)).toBase58();
    if (mintAuthorityOption !== 1 || authorityPk !== mintAuthority) {
      throw new Error("Invalid mint authority");
    }
    if (tokenAccountMint(destination) !== ix.keys[0].pubkey.toBase58()) {
      throw new Error("Destination mint mismatch");
    }
    const amount = readU64LE(ix.data, 1);
    setTokenAccountAmount(destination, tokenAccountAmount(destination) + amount);
    setMintSupply(mint, mintSupply(mint) + amount);
    return;
  }

  if (disc === 3) {
    if (ix.keys.length < 3 || ix.data.length < 9) {
      throw new Error("Invalid Transfer instruction");
    }
    const source = ensureTokenAccount(getAccount(ix.keys[0].pubkey));
    const destination = ensureTokenAccount(getAccount(ix.keys[1].pubkey));
    const ownerPk = ensureSigner(ix, signerSet, 2);
    if (tokenAccountOwner(source) !== ownerPk) {
      throw new Error("Invalid token owner");
    }
    if (tokenAccountMint(source) !== tokenAccountMint(destination)) {
      throw new Error("Mint mismatch");
    }
    const amount = readU64LE(ix.data, 1);
    const srcAmount = tokenAccountAmount(source);
    if (srcAmount < amount) {
      throw new Error("Insufficient token funds");
    }
    setTokenAccountAmount(source, srcAmount - amount);
    setTokenAccountAmount(destination, tokenAccountAmount(destination) + amount);
    return;
  }

  if (disc === 12) {
    if (ix.keys.length < 4 || ix.data.length < 10) {
      throw new Error("Invalid TransferChecked instruction");
    }
    const source = ensureTokenAccount(getAccount(ix.keys[0].pubkey));
    const mint = ensureMintAccount(getAccount(ix.keys[1].pubkey));
    const destination = ensureTokenAccount(getAccount(ix.keys[2].pubkey));
    const ownerPk = ensureSigner(ix, signerSet, 3);
    if (tokenAccountOwner(source) !== ownerPk) {
      throw new Error("Invalid token owner");
    }
    if (tokenAccountMint(source) !== ix.keys[1].pubkey.toBase58()) {
      throw new Error("Source mint mismatch");
    }
    if (tokenAccountMint(destination) !== ix.keys[1].pubkey.toBase58()) {
      throw new Error("Destination mint mismatch");
    }
    const amount = readU64LE(ix.data, 1);
    const decimals = ix.data.readUInt8(9);
    if (decimals !== mintDecimals(mint)) {
      throw new Error("Decimals mismatch");
    }
    const srcAmount = tokenAccountAmount(source);
    if (srcAmount < amount) {
      throw new Error("Insufficient token funds");
    }
    setTokenAccountAmount(source, srcAmount - amount);
    setTokenAccountAmount(destination, tokenAccountAmount(destination) + amount);
    return;
  }

  if (disc === 8) {
    if (ix.keys.length < 3 || ix.data.length < 9) {
      throw new Error("Invalid Burn instruction");
    }
    const tokenAcc = ensureTokenAccount(getAccount(ix.keys[0].pubkey));
    const mint = ensureMintAccount(getAccount(ix.keys[1].pubkey));
    const ownerPk = ensureSigner(ix, signerSet, 2);
    if (tokenAccountOwner(tokenAcc) !== ownerPk) {
      throw new Error("Invalid token owner");
    }
    if (tokenAccountMint(tokenAcc) !== ix.keys[1].pubkey.toBase58()) {
      throw new Error("Mint mismatch");
    }
    const amount = readU64LE(ix.data, 1);
    const bal = tokenAccountAmount(tokenAcc);
    if (bal < amount) {
      throw new Error("Insufficient token funds");
    }
    setTokenAccountAmount(tokenAcc, bal - amount);
    setMintSupply(mint, mintSupply(mint) - amount);
    return;
  }

  if (disc === 9) {
    if (ix.keys.length < 3) {
      throw new Error("Invalid CloseAccount instruction");
    }
    const closing = ensureTokenAccount(getAccount(ix.keys[0].pubkey));
    const destination = getOrCreateSystemAccount(ix.keys[1].pubkey);
    const ownerPk = ensureSigner(ix, signerSet, 2);
    if (tokenAccountOwner(closing) !== ownerPk) {
      throw new Error("Invalid token owner");
    }
    if (tokenAccountAmount(closing) !== 0n) {
      throw new Error("Cannot close non-empty token account");
    }
    destination.lamports += closing.lamports;
    accounts.delete(ix.keys[0].pubkey.toBase58());
    return;
  }

  throw new Error(`Unsupported Token instruction: ${disc}`);
}

function executeAtaInstruction(ix: NormalizedInstruction, signerSet: Set<string>) {
  if (ix.keys.length < 6) {
    throw new Error("Invalid ATA instruction accounts");
  }
  if (!(ix.data.length === 0 || (ix.data.length >= 1 && ix.data.readUInt8(0) === 0))) {
    throw new Error("Unsupported ATA instruction");
  }

  const payerPk = ensureSigner(ix, signerSet, 0);
  const ataPk = ix.keys[1].pubkey;
  const ownerPk = ix.keys[2].pubkey;
  const mintPk = ix.keys[3].pubkey;
  const systemProgramPk = ix.keys[4].pubkey;
  const tokenProgramPk = ix.keys[5].pubkey;

  if (!systemProgramPk.equals(SYSTEM_PROGRAM_ID)) {
    throw new Error("Invalid system program account");
  }
  if (!tokenProgramPk.equals(TOKEN_PROGRAM_ID)) {
    throw new Error("Invalid token program account");
  }

  const [derivedAta] = PublicKey.findProgramAddressSync(
    [ownerPk.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mintPk.toBuffer()],
    ATA_PROGRAM_ID,
  );
  if (!derivedAta.equals(ataPk)) {
    throw new Error("Invalid associated token account address");
  }

  const existing = getAccount(ataPk);
  if (existing && (existing.lamports > 0n || existing.data.length > 0)) {
    throw new Error("ATA already exists");
  }

  const payer = getOrCreateSystemAccount(new PublicKey(payerPk));
  const mint = ensureMintAccount(getAccount(mintPk));
  const rent = BigInt(rentExemptMin(165));
  if (payer.lamports < rent) {
    throw new Error("Insufficient funds for ATA creation");
  }

  payer.lamports -= rent;
  const ataAccount: LedgerAccount = {
    pubkey: ataPk.toBase58(),
    lamports: rent,
    owner: TOKEN_PROGRAM_ID.toBase58(),
    data: Buffer.alloc(165),
    executable: false,
    rentEpoch: 0,
  };
  mintPk.toBuffer().copy(ataAccount.data, 0);
  ownerPk.toBuffer().copy(ataAccount.data, 32);
  writeU64LE(ataAccount.data, 64, 0n);
  ataAccount.data.fill(0, 72, 108);
  ataAccount.data.writeUInt8(1, 108);
  ataAccount.data.fill(0, 109, 121);
  writeU64LE(ataAccount.data, 121, 0n);
  ataAccount.data.fill(0, 129, 165);
  if (mint.data[45] !== 1) {
    throw new Error("Mint not initialized");
  }
  accounts.set(ataPk.toBase58(), ataAccount);
}

function executeTransaction(parsed: ParsedTransaction) {
  if (!issuedBlockhashes.has(parsed.recentBlockhash)) {
    throw new Error("Blockhash not found");
  }

  for (const ix of parsed.instructions) {
    if (ix.programId.equals(SYSTEM_PROGRAM_ID)) {
      executeSystemInstruction(ix, parsed.signerSet);
      continue;
    }
    if (ix.programId.equals(TOKEN_PROGRAM_ID)) {
      executeTokenInstruction(ix, parsed.signerSet);
      continue;
    }
    if (ix.programId.equals(ATA_PROGRAM_ID)) {
      executeAtaInstruction(ix, parsed.signerSet);
      continue;
    }
    throw new Error(`Unsupported program ${ix.programId.toBase58()}`);
  }
}

function cloneLedgerAccounts() {
  const cloned = new Map<string, LedgerAccount>();
  for (const [k, v] of accounts.entries()) {
    cloned.set(k, {
      pubkey: v.pubkey,
      lamports: v.lamports,
      owner: v.owner,
      data: Buffer.from(v.data),
      executable: v.executable,
      rentEpoch: v.rentEpoch,
    });
  }
  return cloned;
}

app.post("/", (req, res) => {
  const body = req.body;
  if (!body || typeof body !== "object") {
    return res.status(400).json(rpcError(null, RPC_INVALID_REQUEST, "Invalid request"));
  }

  const { jsonrpc, id, method, params } = body;
  if (jsonrpc !== "2.0" || typeof method !== "string") {
    return res.status(400).json(rpcError(id ?? null, RPC_INVALID_REQUEST, "Invalid request"));
  }

  try {
    switch (method) {
      case "getVersion":
        return res.json(rpcResult(id, { "solana-core": "1.18.0", "feature-set": 1 }));

      case "getSlot":
        return res.json(rpcResult(id, slot));

      case "getBlockHeight":
        return res.json(rpcResult(id, blockHeight));

      case "getHealth":
        return res.json(rpcResult(id, "ok"));

      case "getLatestBlockhash": {
        const blockhash = bs58.encode(randomBytes(32));
        const lastValidBlockHeight = blockHeight + 150;
        issuedBlockhashes.set(blockhash, lastValidBlockHeight);
        return res.json(
          rpcResult(id, {
            context: { slot },
            value: { blockhash, lastValidBlockHeight },
          }),
        );
      }

      case "getBalance": {
        if (!Array.isArray(params) || params.length < 1) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const pubkey = toPublicKey(params[0]);
        const account = getAccount(pubkey);
        return res.json(rpcResult(id, { context: { slot }, value: Number(account?.lamports ?? 0n) }));
      }

      case "getAccountInfo": {
        if (!Array.isArray(params) || params.length < 1) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        if (
          params[1] &&
          (typeof params[1] !== "object" ||
            params[1] === null ||
            ("encoding" in (params[1] as Record<string, unknown>) &&
              (params[1] as { encoding?: string }).encoding !== "base64"))
        ) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const pubkey = toPublicKey(params[0]);
        const account = getAccount(pubkey);
        return res.json(
          rpcResult(id, {
            context: { slot },
            value: account ? toRpcAccountInfo(account) : null,
          }),
        );
      }

      case "getMinimumBalanceForRentExemption": {
        if (!Array.isArray(params) || params.length < 1 || typeof params[0] !== "number") {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        return res.json(rpcResult(id, rentExemptMin(params[0])));
      }

      case "getTokenAccountBalance": {
        if (!Array.isArray(params) || params.length < 1) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const account = ensureTokenAccount(getAccount(toPublicKey(params[0])));
        const mint = ensureMintAccount(getAccount(new PublicKey(account.data.subarray(0, 32))));
        const amount = tokenAccountAmount(account);
        const decimals = mintDecimals(mint);
        const uiAmount = Number(amount) / 10 ** decimals;
        return res.json(
          rpcResult(id, {
            context: { slot },
            value: {
              amount: amount.toString(),
              decimals,
              uiAmount,
            },
          }),
        );
      }

      case "getTokenAccountsByOwner": {
        if (!Array.isArray(params) || params.length < 2) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const owner = toPublicKey(params[0]).toBase58();
        const filter = params[1] as { mint?: string; programId?: string };
        if (!filter || typeof filter !== "object" || (!filter.mint && !filter.programId)) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        if (filter.mint && typeof filter.mint !== "string") {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        if (filter.programId && typeof filter.programId !== "string") {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        if (
          params[2] &&
          (typeof params[2] !== "object" ||
            params[2] === null ||
            (params[2] as { encoding?: string }).encoding !== "base64")
        ) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const out: Array<{ pubkey: string; account: ReturnType<typeof toRpcAccountInfo> }> = [];

        for (const acc of accounts.values()) {
          if (acc.owner !== TOKEN_PROGRAM_ID.toBase58() || acc.data.length < 165) {
            continue;
          }
          if (tokenAccountOwner(acc) !== owner) {
            continue;
          }

          if (filter?.mint && tokenAccountMint(acc) !== filter.mint) {
            continue;
          }
          if (filter?.programId && filter.programId !== TOKEN_PROGRAM_ID.toBase58()) {
            continue;
          }

          out.push({ pubkey: acc.pubkey, account: toRpcAccountInfo(acc) });
        }

        return res.json(rpcResult(id, { context: { slot }, value: out }));
      }

      case "requestAirdrop": {
        if (!Array.isArray(params) || params.length < 2) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const pubkey = toPublicKey(params[0]);
        const lamports = toBigIntAmount(params[1]);
        const account = getOrCreateSystemAccount(pubkey);
        account.lamports += lamports;
        const signature = bs58.encode(randomBytes(64));
        signatureStatuses.set(signature, {
          slot,
          confirmations: null,
          err: null,
          confirmationStatus: "confirmed",
        });
        return res.json(rpcResult(id, signature));
      }

      case "sendTransaction": {
        if (!Array.isArray(params) || params.length < 1 || typeof params[0] !== "string") {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        if (
          params[1] &&
          (typeof params[1] !== "object" ||
            params[1] === null ||
            ("encoding" in (params[1] as Record<string, unknown>) &&
              (params[1] as { encoding?: string }).encoding !== "base64"))
        ) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }

        try {
          const parsed = parseAndVerifyTransaction(params[0]);
          const snapshot = cloneLedgerAccounts();
          try {
            executeTransaction(parsed);
          } catch (txErr) {
            accounts.clear();
            for (const [k, v] of snapshot.entries()) {
              accounts.set(k, v);
            }
            throw txErr;
          }

          slot += 1;
          blockHeight += 1;

          const signature = parsed.signatures[0];
          signatureStatuses.set(signature, {
            slot,
            confirmations: null,
            err: null,
            confirmationStatus: "confirmed",
          });
          return res.json(rpcResult(id, signature));
        } catch (err) {
          return res.json(
            rpcError(id, RPC_TX_FAILED, err instanceof Error ? err.message : "Transaction failed"),
          );
        }
      }

      case "getSignatureStatuses": {
        if (!Array.isArray(params) || params.length < 1 || !Array.isArray(params[0])) {
          return res.json(rpcError(id, RPC_INVALID_PARAMS, "Invalid params"));
        }
        const values = (params[0] as unknown[]).map((s) => {
          if (typeof s !== "string") {
            return null;
          }
          return signatureStatuses.get(s) ?? null;
        });
        return res.json(rpcResult(id, { context: { slot }, value: values }));
      }

      default:
        return res.json(rpcError(id, RPC_METHOD_NOT_FOUND, "Method not found"));
    }
  } catch (err) {
    return res.json(rpcError(id, RPC_INVALID_PARAMS, err instanceof Error ? err.message : "Invalid params"));
  }
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof SyntaxError) {
    return res.status(400).json(rpcError(null, RPC_INVALID_REQUEST, "Invalid request"));
  }
  return res.status(500).json(rpcError(null, RPC_INVALID_REQUEST, "Invalid request"));
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Mini Solana Validator running on port ${PORT}`);
});
