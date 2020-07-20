//
//  TransactionSigner.swift
//  
//  Copyright © 2019 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

public enum TransactionSignerError: Error {
    case noKeyFound
}

/// Helper class that performs Bitcoin transaction signing.
/// ```
/// // Initialize a signer
/// let signer = TransactionSigner(unspentTransactions: unspentTransactions, transaction: transaction, sighashHelper: sighashHelper)
///
/// // Sign the unsigned transaction
/// let signedTx = signer.sign(with: privKeys)
/// ```
public final class TransactionSigner {
    /// Unspent transactions to be signed.
    public let unspentTransactions: [UnspentTransaction]
    /// Transaction being signed.
    public let transaction: Transaction
    /// Signature Hash Helper
    public let sighashHelper: SignatureHashHelper

    /// List of signed inputs.
    private var signedInputs: [TransactionInput]
    /// Signed transaction
    private var signedTransaction: Transaction {
        return Transaction(
            version: transaction.version,
            inputs: signedInputs,
            outputs: transaction.outputs,
            lockTime: transaction.lockTime)
    }

    public init(unspentTransactions: [UnspentTransaction], transaction: Transaction, sighashHelper: SignatureHashHelper) {
        self.unspentTransactions = unspentTransactions
        self.transaction = transaction
        self.signedInputs = transaction.inputs
        self.sighashHelper = sighashHelper
    }

    /// Sign the transaction with keys of the unspent transactions
    ///
    /// - Parameters:
    ///   - keys: the private keys of the unspent transactions
    /// - Returns: A signed transaction. Error is thrown when the signing failed.
    public func sign(with keys: [PrivateKey]) throws -> Transaction {
        for (i, unspentTransaction) in unspentTransactions.enumerated() {
            // Select key
            let utxo = unspentTransaction.output
            let pubkeyHash: Data = Script.getPublicKeyHash(from: utxo.lockingScript)

            guard let key = keys.first(where: { $0.publicKey().pubkeyHash == pubkeyHash }) else {
                throw TransactionSignerError.noKeyFound
            }

            // Sign transaction hash
            let sighash: Data = sighashHelper.createSignatureHash(of: transaction, for: utxo, inputIndex: i)
            let signature: Data = try Crypto.sign(sighash, privateKey: key)
            let txin = signedInputs[i]
            let pubkey = key.publicKey()

            // Create Signature Script
            let sigWithHashType: Data = signature + [sighashHelper.hashType.uint8]
            let unlockingScript: Script = try Script()
                .appendData(sigWithHashType)
                .appendData(pubkey.data)

            // Update TransactionInput
            signedInputs[i] = TransactionInput(previousOutput: txin.previousOutput, signatureScript: unlockingScript.data, sequence: txin.sequence)
        }
        return signedTransaction
    }
}

extension TransactionSigner {
    struct InputSignature {
        let script: Data
        let witness: [Data]
    }

    public static func witnessSignatureP2SH_P2WPKH(rawTransaction: Data, inputValues: [UInt64], privateKey: PrivateKey) throws -> Data {
        let transaction = Transaction.deserialize(rawTransaction)
        let sigHashes = TxSigHashes(tx: transaction)
        let witnessProgram = try Script().append(.OP_0).appendData(privateKey.publicKey().pubkeyHash).data

        var signatures = [InputSignature]()
        for index in 0..<transaction.inputs.count {
            let signatureScript = try Script().appendData(witnessProgram).data

            let signatureHash = try calcWitnessSignatureHash(pubkeyHash: privateKey.publicKey().pubkeyHash, sigHashes: sigHashes, tx: transaction, idx: index, amount: inputValues[index])
            var signature = privateKey.sign(signatureHash)
            signature += UInt8(0x1) // SigHashType -- SigHashAll = 0x1
            let witness = [signature, privateKey.publicKey().data]

            signatures.append(.init(script: signatureScript, witness: witness))
        }

        return serializeTx(transaction, signatures: signatures)
    }

    static func serializeTx(_ tx: Transaction, signatures: [InputSignature]) -> Data {
        var data = Data()

        data += UInt32(tx.version)
        data += [UInt8(0x00), UInt8(0x01)] // witessMarkerBytes

        // writeTxIn
        data.writeVarInt(UInt64(tx.inputs.count))
        for (i, input) in tx.inputs.enumerated() {
            data += input.previousOutput.hash
            data += UInt32(input.previousOutput.index)
            data.writeVarBytes(signatures[i].script)
            data += UInt32(input.sequence)
        }

        // writeTxOut
        data.writeVarInt(UInt64(tx.outputs.count))
        for output in tx.outputs {
            data += UInt64(output.value)
            data.writeVarBytes(output.lockingScript)
        }

        // writeTxWitness
        for (i, _) in tx.inputs.enumerated() {
            let witness = signatures[i].witness
            data.writeVarInt(UInt64(witness.count))
            for item in witness {
                data.writeVarBytes(item)
            }
        }

        data += UInt32(tx.lockTime)
        return data
    }

    static func calcWitnessSignatureHash(pubkeyHash: Data, sigHashes: TxSigHashes, tx: Transaction, idx: Int, amount: UInt64) throws -> Data {
        if idx >= tx.inputs.count {
            throw NSError(domain: "idx \(idx) but \(tx.inputs.count) txins", code: -1, userInfo: nil)
        }

        var sigHash = Data()

        sigHash += UInt32(tx.version)

        sigHash += sigHashes.hashPrevOuts
        sigHash += sigHashes.hashSequence

        let input = tx.inputs[idx]
        sigHash += input.previousOutput.hash
        sigHash += UInt32(input.previousOutput.index)

        sigHash += UInt8(0x19)
        sigHash += OpCode.OP_DUP.value
        sigHash += OpCode.OP_HASH160.value
        sigHash += UInt8(0x14) // OP_DATA_20
        sigHash += pubkeyHash
        sigHash += OpCode.OP_EQUALVERIFY.value
        sigHash += OpCode.OP_CHECKSIG.value

        sigHash += UInt64(amount)
        sigHash += UInt32(input.sequence)

        sigHash += sigHashes.hashOutputs

        sigHash += UInt32(tx.lockTime)
        sigHash += UInt32(1) // sign type

        let signatureHash = Crypto.sha256sha256(sigHash)
        return signatureHash
    }
}

struct TxSigHashes: CustomStringConvertible {
    var hashPrevOuts: Data
    var hashSequence: Data
    var hashOutputs: Data

    init(tx: Transaction) {
        hashPrevOuts = calcHashPrevOuts(tx)
        hashSequence = calcHashSequence(tx)
        hashOutputs = calcHashOutputs(tx)
    }

    var description: String {
        """
        hashPrevOuts: \(hashPrevOuts.hex)
        hashSequence: \(hashSequence.hex)
        hashOutputs: \(hashOutputs.hex)
        """
    }
}

func calcHashPrevOuts(_ tx: Transaction) -> Data {
    var data = Data()
    for input in tx.inputs {
        data += input.previousOutput.hash
        data += input.previousOutput.index
    }
    return Crypto.sha256sha256(data)
}

func calcHashSequence(_ tx: Transaction) -> Data {
    var data = Data()
    for input in tx.inputs {
        data += input.sequence
    }
    return Crypto.sha256sha256(data)
}

func calcHashOutputs(_ tx: Transaction) -> Data {
    var data = Data()
    for output in tx.outputs {
        data += UInt64(output.value)
        data.writeVarBytes(output.lockingScript)
    }
    return Crypto.sha256sha256(data)
}

extension Data {
    mutating func writeVarInt(_ value: UInt64) {
        if value < 0xfd {
            self += UInt8(value)
        } else if value <= UInt16.max {
            self += UInt8(0xfd)
            self += UInt16(value)
        } else if value <= UInt32.max {
            self += UInt8(0xfe)
            self += UInt32(value)
        } else {
            self += UInt8(0xff)
            self += UInt64(value)
        }
    }

    mutating func writeVarBytes(_ data: Data) {
        writeVarInt(UInt64(data.count))
        self += data
    }
}
