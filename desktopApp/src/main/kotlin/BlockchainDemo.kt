import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.Key
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.time.Instant
import java.util.Base64
import kotlin.random.Random

private fun String.sha256(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(toByteArray())
    return String.format("%064x", BigInteger(1, digest.digest()))
}

private fun String.sign(privateKey: PrivateKey): ByteArray {
    val rsa = Signature.getInstance("SHA256withRSA")
    rsa.initSign(privateKey)
    rsa.update(toByteArray())
    return rsa.sign()
}

private fun String.verifySignature(publicKey: PublicKey, signature: ByteArray): Boolean {
    val rsa = Signature.getInstance("SHA256withRSA")
    rsa.initVerify(publicKey)
    rsa.update(toByteArray())
    return rsa.verify(signature)
}

private fun Key.encodeToString(): String = Base64.getEncoder().encodeToString(this.encoded)

private data class TransactionOutput(
    val recipient: PublicKey,
    val amount: Int,
    val transactionHash: String,
    val hash: String = "${recipient.encodeToString()}$amount$transactionHash".sha256()
) {
    fun isMine(me: PublicKey): Boolean = recipient == me
}

private data class Transaction(
    val sender: PublicKey?,
    val recipient: PublicKey,
    val amount: Int,
    val inputs: MutableList<TransactionOutput> = mutableListOf(),
    val outputs: MutableList<TransactionOutput> = mutableListOf(),
    val isCoinbase: Boolean = false,
    val hash: String,
    private var signature: ByteArray = ByteArray(0)
) {
    companion object {
        private var salt = 0L

        fun create(sender: PublicKey, recipient: PublicKey, amount: Int): Transaction {
            val txHash = "${sender.encodeToString()}${recipient.encodeToString()}$amount${salt++}".sha256()
            return Transaction(sender, recipient, amount, hash = txHash)
        }

        fun coinbase(recipient: PublicKey, amount: Int): Transaction {
            val txHash = "COINBASE${recipient.encodeToString()}$amount${salt++}".sha256()
            val tx = Transaction(sender = null, recipient = recipient, amount = amount, isCoinbase = true, hash = txHash)
            tx.outputs.add(TransactionOutput(recipient = recipient, amount = amount, transactionHash = tx.hash))
            return tx
        }
    }

    fun sign(privateKey: PrivateKey): Transaction {
        if (isCoinbase || sender == null) return this
        signature = "${sender.encodeToString()}${recipient.encodeToString()}$amount".sign(privateKey)
        return this
    }

    fun isSignatureValid(): Boolean {
        if (isCoinbase || sender == null) return true
        return "${sender.encodeToString()}${recipient.encodeToString()}$amount".verifySignature(sender, signature)
    }
}

private data class Block(
    val previousHash: String,
    val transactions: MutableList<Transaction> = mutableListOf(),
    val timestamp: Long = Instant.now().toEpochMilli(),
    val nonce: Long = 0,
    val hash: String = ""
) {
    fun calculateHash(): String = "$previousHash$transactions$timestamp$nonce".sha256()

    fun withTransaction(transaction: Transaction): Block {
        if (transaction.isSignatureValid()) transactions.add(transaction)
        return this
    }
}

private data class MineResult(val block: Block, val attempts: Long, val millis: Long)

private class BlockChain(private val difficulty: Int = 3) {
    private val validPrefix = "0".repeat(difficulty)
    val blocks: MutableList<Block> = mutableListOf()
    val utxo: MutableMap<String, TransactionOutput> = mutableMapOf()

    fun add(block: Block): MineResult {
        val result = if (isMined(block)) MineResult(block, 1, 0) else mine(block)
        blocks.add(result.block)
        return result
    }

    fun isValid(): Boolean {
        if (blocks.isEmpty()) return true
        for (i in blocks.indices) {
            val current = blocks[i]
            if (current.hash != current.calculateHash()) return false
            if (!isMined(current)) return false
            if (i > 0 && current.previousHash != blocks[i - 1].hash) return false
        }
        return true
    }

    fun tamperLastBlock() {
        if (blocks.isEmpty()) return
        val index = blocks.lastIndex
        val target = blocks[index]
        if (target.transactions.isEmpty()) return
        val hacked = target.transactions[0].copy(amount = target.transactions[0].amount + 7)
        blocks[index] = target.copy(transactions = target.transactions.toMutableList().apply { this[0] = hacked })
    }

    private fun isMined(block: Block): Boolean = block.hash.startsWith(validPrefix)

    private fun mine(block: Block): MineResult {
        val started = System.currentTimeMillis()
        var attempts = 0L
        var candidate = block.copy(hash = block.calculateHash())

        while (!isMined(candidate)) {
            attempts++
            val nextNonce = candidate.nonce + 1
            candidate = candidate.copy(
                nonce = nextNonce,
                hash = "${candidate.previousHash}${candidate.transactions}${candidate.timestamp}$nextNonce".sha256()
            )
        }

        val done = System.currentTimeMillis()
        updateUtxo(candidate)
        return MineResult(block = candidate, attempts = attempts + 1, millis = done - started)
    }

    private fun updateUtxo(block: Block) {
        block.transactions.flatMap { it.inputs }.map { it.hash }.forEach { utxo.remove(it) }
        utxo.putAll(block.transactions.flatMap { it.outputs }.associateBy { it.hash })
    }
}

private data class Wallet(val publicKey: PublicKey, val privateKey: PrivateKey, val chain: BlockChain) {
    companion object {
        fun create(chain: BlockChain): Wallet {
            val generator = KeyPairGenerator.getInstance("RSA")
            generator.initialize(2048)
            val keyPair = generator.generateKeyPair()
            return Wallet(keyPair.public, keyPair.private, chain)
        }
    }

    val balance: Int
        get() = myOutputs().sumOf { it.amount }

    fun sendFundsTo(recipient: PublicKey, amountToSend: Int): Transaction {
        require(amountToSend > 0) { "Amount must be > 0" }
        require(amountToSend <= balance) { "Insufficient funds" }

        val tx = Transaction.create(sender = publicKey, recipient = recipient, amount = amountToSend)
        tx.outputs.add(TransactionOutput(recipient = recipient, amount = amountToSend, transactionHash = tx.hash))

        var collected = 0
        for (mine in myOutputs()) {
            collected += mine.amount
            tx.inputs.add(mine)
            if (collected > amountToSend) {
                tx.outputs.add(
                    TransactionOutput(
                        recipient = publicKey,
                        amount = collected - amountToSend,
                        transactionHash = tx.hash
                    )
                )
            }
            if (collected >= amountToSend) break
        }

        return tx.sign(privateKey)
    }

    private fun myOutputs(): Collection<TransactionOutput> = chain.utxo.filterValues { it.isMine(publicKey) }.values
}

private class BlockchainDemo {
    val chain = BlockChain(difficulty = 3)
    private val users = linkedMapOf<String, Wallet>()
    private val pending = mutableListOf<Transaction>()
    private val random = Random(System.currentTimeMillis())

    var lastMiningAttempts: Long = 0
    var lastMiningMillis: Long = 0

    init {
        users["Alice"] = Wallet.create(chain)
        users["Bob"] = Wallet.create(chain)
        users["Charlie"] = Wallet.create(chain)
        users["Miner"] = Wallet.create(chain)

        val genesis = Block(previousHash = "0")
            .withTransaction(Transaction.coinbase(users.getValue("Alice").publicKey, 120))
            .withTransaction(Transaction.coinbase(users.getValue("Bob").publicKey, 60))
        chain.add(genesis)
    }

    fun balances(): Map<String, Int> = users.mapValues { (_, wallet) -> wallet.balance }

    fun enqueueTransfer(from: String, to: String, amount: Int): String {
        val sender = users.getValue(from)
        val recipient = users.getValue(to)
        val tx = sender.sendFundsTo(recipient.publicKey, amount)
        pending.add(tx)
        return "Queued: $from -> $to ($amount)"
    }

    fun randomTransactionOrNull(): String {
        val names = users.keys.filter { it != "Miner" }
        repeat(8) {
            val from = names[random.nextInt(names.size)]
            val toCandidates = names.filter { it != from }
            val to = toCandidates[random.nextInt(toCandidates.size)]
            val max = users.getValue(from).balance
            if (max <= 1) return@repeat
            val amount = random.nextInt(1, max.coerceAtMost(15) + 1)
            return runCatching { enqueueTransfer(from, to, amount) }
                .getOrElse { "Rejected tx: ${it.message}" }
        }
        return "No valid random tx (insufficient spendable funds)"
    }

    fun minePendingBlock(): String {
        val miner = users.getValue("Miner")
        val reward = Transaction.coinbase(miner.publicKey, 12)
        val block = Block(previousHash = chain.blocks.last().hash)
        pending.forEach { block.withTransaction(it) }
        block.withTransaction(reward)

        val txCount = pending.size
        val result = chain.add(block)
        pending.clear()

        lastMiningAttempts = result.attempts
        lastMiningMillis = result.millis

        return "Mined block #${chain.blocks.lastIndex} with $txCount tx in ${result.millis} ms (${result.attempts} hashes)"
    }

    fun tamperLastBlock() {
        chain.tamperLastBlock()
    }

    fun pendingCount(): Int = pending.size
}

@Composable
fun BlockchainDesktopDemo() {
    val demo = remember { BlockchainDemo() }
    val scope = rememberCoroutineScope()

    var amountText by remember { mutableStateOf("10") }
    var status by remember { mutableStateOf("Genesis created. Auto mode simulates mempool + mining.") }
    var mining by remember { mutableStateOf(false) }
    var autoMode by remember { mutableStateOf(true) }
    var refreshTick by remember { mutableStateOf(0) }

    fun refresh() {
        refreshTick += 1
    }

    if (autoMode) {
        androidx.compose.runtime.LaunchedEffect(autoMode) {
            while (isActive && autoMode) {
                status = demo.randomTransactionOrNull()
                refresh()
                delay(900)

                if (!mining && demo.pendingCount() >= 2) {
                    mining = true
                    status = withContext(Dispatchers.Default) { demo.minePendingBlock() }
                    mining = false
                    refresh()
                }
                delay(1700)
            }
        }
    }

    MaterialTheme {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.linearGradient(
                        colors = listOf(Color(0xFFF9F1E7), Color(0xFFE9F2FA), Color(0xFFF7EFE6))
                    )
                )
        ) {
            Column(
                modifier = Modifier.fillMaxSize().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text("Blockchain Simulator", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("Desktop-only live demo: mempool, PoW, rewards, UTXO, validation", color = MaterialTheme.colorScheme.onSurfaceVariant)

                Card(colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.84f))) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        demo.balances().forEach { (name, value) -> MetricChip(title = name, value = "$value") }
                        MetricChip(title = "Mempool", value = "${demo.pendingCount()}")
                        MetricChip(title = "Blocks", value = "${demo.chain.blocks.size}")
                        MetricChip(title = "Integrity", value = if (demo.chain.isValid()) "VALID" else "BROKEN")
                        MetricChip(title = "Last Mine", value = "${demo.lastMiningMillis} ms")
                    }
                }

                Card(colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.84f))) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = amountText,
                            onValueChange = { amountText = it.filter(Char::isDigit) },
                            label = { Text("Alice -> Bob amount") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.width(190.dp)
                        )

                        Button(enabled = !mining, onClick = {
                            val amount = amountText.toIntOrNull() ?: 0
                            status = runCatching { demo.enqueueTransfer("Alice", "Bob", amount) }
                                .getOrElse { "Tx failed: ${it.message}" }
                            refresh()
                        }) { Text("Add Tx") }

                        Button(enabled = !mining, onClick = {
                            scope.launch {
                                mining = true
                                status = withContext(Dispatchers.Default) { demo.minePendingBlock() }
                                mining = false
                                refresh()
                            }
                        }) { Text(if (mining) "Mining..." else "Mine Now") }

                        Button(onClick = {
                            autoMode = !autoMode
                            status = if (autoMode) "Auto mode enabled" else "Auto mode paused"
                            refresh()
                        }) { Text(if (autoMode) "Pause Auto" else "Start Auto") }

                        Button(enabled = !mining, onClick = {
                            demo.tamperLastBlock()
                            status = "Tampered latest block. Validation should fail now."
                            refresh()
                        }) { Text("Tamper") }
                    }
                }

                Text(status, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
                Text("Last nonce search: ${demo.lastMiningAttempts} hashes", color = MaterialTheme.colorScheme.onSurfaceVariant)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    demo.chain.blocks.forEachIndexed { index, block ->
                        BlockCard(index = index, block = block, isValid = demo.chain.isValid())
                    }
                }

                Text("Tick: $refreshTick", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun MetricChip(title: String, value: String) {
    Column(
        modifier = Modifier
            .border(1.dp, Color(0xFFD0DBEE), RoundedCornerShape(14.dp))
            .padding(PaddingValues(horizontal = 12.dp, vertical = 8.dp))
    ) {
        Text(title, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun BlockCard(index: Int, block: Block, isValid: Boolean) {
    Card(
        modifier = Modifier.width(320.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isValid) Color(0xFFFFFCF7) else Color(0xFFFFECEC)
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text("Block #$index", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text("Hash: ${block.hash.take(20)}...", color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Prev: ${block.previousHash.take(20)}...", color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Nonce: ${block.nonce}")
            Text("Tx count: ${block.transactions.size}")
            Text("Mined at: ${block.timestamp}")
        }
    }
}
