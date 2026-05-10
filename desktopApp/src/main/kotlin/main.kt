import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import java.awt.Dimension

fun main() = application {
    Window(
        title = "Blockchain",
        state = rememberWindowState(width = 1280.dp, height = 820.dp),
        onCloseRequest = ::exitApplication,
    ) {
        window.minimumSize = Dimension(1000, 720)
        BlockchainDesktopDemo()
    }
}
