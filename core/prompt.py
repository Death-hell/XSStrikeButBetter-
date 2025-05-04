import os
import tempfile

from core.config import defaultEditor
from core.colors import white, yellow
from core.log import setup_logger

logger = setup_logger(__name__)


def prompt(default: str = None) -> str:
    editor = os.environ.get('EDITOR', defaultEditor)

    with tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmpfile:
        if default:
            tmpfile.write(default)
            tmpfile.flush()

        pid = os.fork()
        if pid == 0:
            # Processo filho: abre o editor
            try:
                os.execvp(editor, [editor, tmpfile.name])
            except FileNotFoundError:
                logger.error("Nenhum editor padrão definido via $EDITOR e 'nano' não encontrado.")
                logger.info(f"Execute {yellow}export EDITOR=/path/to/editor{white} e rode novamente.")
                os._exit(1)
        else:
            # Processo pai: espera o filho terminar
            os.waitpid(pid, 0)
            with open(tmpfile.name, 'r') as f:
                content = f.read().strip()
            os.unlink(tmpfile.name)  # remove o arquivo temporário
            return content
