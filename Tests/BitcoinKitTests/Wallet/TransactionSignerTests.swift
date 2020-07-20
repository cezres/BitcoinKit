//
//  TransactionSignerTests.swift
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

import XCTest
@testable import BitcoinKit

class TransactionSignerTests: XCTestCase {
    func testSign() {
        // Transaction on Bitcoin Cash Mainnet
        // TxID : 96ee20002b34e468f9d3c5ee54f6a8ddaa61c118889c4f35395c2cd93ba5bbb4
        // https://explorer.bitcoin.com/bch/tx/96ee20002b34e468f9d3c5ee54f6a8ddaa61c118889c4f35395c2cd93ba5bbb4
        
        // TransactionOutput
        let prevTxLockScript = Data(hex: "76a914aff1e0789e5fe316b729577665aa0a04d5b0f8c788ac")
        let prevTxOutput = TransactionOutput(value: 5151, lockingScript: prevTxLockScript!)
        
        // TransactionOutpoint
        let prevTxID = "050d00e2e18ef13969606f1ceee290d3f49bd940684ce39898159352952b8ce2"
        let prevTxHash = Data(Data(hex: prevTxID)!.reversed())
        let prevTxOutPoint = TransactionOutPoint(hash: prevTxHash, index: 2)
        
        // UnspentTransaction
        let unspentTransaction = UnspentTransaction(output: prevTxOutput,
                                      outpoint: prevTxOutPoint)
        let plan = TransactionPlan(unspentTransactions: [unspentTransaction], amount: 600, fee: 226, change: 4325)
        let toAddress = try! BitcoinAddress(cashaddr: "bitcoincash:qpmfhhledgp0jy66r5vmwjwmdfu0up7ujqcp07ha9v")
        let changeAddress = try! BitcoinAddress(cashaddr: "bitcoincash:qz0q3xmg38sr94rw8wg45vujah7kzma3cskxymnw06")
        let tx = TransactionBuilder.build(from: plan, toAddress: toAddress, changeAddress: changeAddress)
        
        let privKey = try! PrivateKey(wif: "L1WFAgk5LxC5NLfuTeADvJ5nm3ooV3cKei5Yi9LJ8ENDfGMBZjdW")
        let signer = TransactionSigner(unspentTransactions: plan.unspentTransactions, transaction: tx, sighashHelper: BCHSignatureHashHelper(hashType: .ALL))
        let signedTx = try! signer.sign(with: [privKey])
        let expected: Data = Data(hex: "0100000001e28c2b955293159898e34c6840d99bf4d390e2ee1c6f606939f18ee1e2000d05020000006b483045022100b70d158b43cbcded60e6977e93f9a84966bc0cec6f2dfd1463d1223a90563f0d02207548d081069de570a494d0967ba388ff02641d91cadb060587ead95a98d4e3534121038eab72ec78e639d02758e7860cdec018b49498c307791f785aa3019622f4ea5bffffffff0258020000000000001976a914769bdff96a02f9135a1d19b749db6a78fe07dc9088ace5100000000000001976a9149e089b6889e032d46e3b915a3392edfd616fb1c488ac00000000")!
        XCTAssertEqual(signedTx.serialized(), expected)
        XCTAssertEqual(signedTx.txID, "96ee20002b34e468f9d3c5ee54f6a8ddaa61c118889c4f35395c2cd93ba5bbb4")
    }

    func testWitnessSignatureP2SH_P2WPKH() throws {
        let seed = try Mnemonic.seed(mnemonic: "travel label harvest demise february device cushion sign soap horn team giggle relax frost flat".components(separatedBy: " "))
        let keychain = HDKeychain(seed: seed, network: .mainnetBTC)
        let key = try keychain.derivedKey(path: "m/49'/1'/0'/0/1")

        let rawTransaction = Data(hex: "0100000001e6638c113bd2e3d1381df6ac26d97392d141dfe7660092d3162790162b9ebefd0100000000ffffffff02983a00000000000017a9141d018b91067a31c039f324778c905caae808a1158714e900000000000017a914f211abebccea466dc5f7d7f17e50d5cd68fb655e8700000000")!

        let result = try TransactionSigner.witnessSignatureP2SH_P2WPKH(rawTransaction: rawTransaction, inputValues: [74834], privateKey: key.privateKey())

        XCTAssertEqual(result.hex, "01000000000101e6638c113bd2e3d1381df6ac26d97392d141dfe7660092d3162790162b9ebefd010000001716001485a78d41d073525afeed3c977e0c2e7d6dff76beffffffff02983a00000000000017a9141d018b91067a31c039f324778c905caae808a1158714e900000000000017a914f211abebccea466dc5f7d7f17e50d5cd68fb655e87024830450221008be94f5b0ace6710ea474cbaaf56fd0d6645627747183388809e3985f18edfc602205214c0814feeeeebb9dcf598a41ab978a2906df33adfea92f22b6e6ab17b937f01210259515492a9e114a08d51c2b37ebb8cfb7349e5bc5ee4782eed2a4eaf9f51f2ec00000000")
    }
}
