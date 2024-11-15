import sys
import logging
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel,
    QTableWidget, QTableWidgetItem, QSpinBox, QComboBox, QProgressBar,
    QMessageBox, QCheckBox, QGridLayout, QLineEdit, QMenu, QTextEdit, QToolButton
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMetaObject, Q_ARG
import subprocess
import os
import re
import winreg  # Windows注册表
import time
from functools import lru_cache
from collections import deque
from concurrent.futures import ThreadPoolExecutor

# 初始化日志
logging.basicConfig(filename='render_log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义配置常量
NUKE_PATHS = {
    "Nuke13.0v4": r"C:\Program Files\Nuke13.0v4\Nuke13.0.exe",
    "Nuke15.1v3": r"C:\Program Files\Nuke15.1v3\Nuke15.1.exe"
}
MAX_THREADS = 4

class RenderThread(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

    def __init__(self, nuke_path, script_path, start_frame, end_frame, render_node, row_index):
        super().__init__()
        self.nuke_path = nuke_path
        self.script_path = script_path
        self.start_frame = start_frame
        self.end_frame = end_frame
        self.render_node = render_node
        self.row_index = row_index
        self.process = None
        self._is_stopped = False

    def run(self):
        # 构建渲染命令
        command = [
            self.nuke_path,
            '-x',
            self.script_path,
            '-F', f'{self.start_frame}-{self.end_frame}',
            '-X', self.render_node
        ]
        logging.debug(f"开始渲染，命令：{' '.join(command)}")

        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            total_frames = self.end_frame - self.start_frame + 1
            progress = 0
            simulated_progress = 0

            while True:
                if self._is_stopped and self.process:
                    self.process.terminate()
                    self.result.emit(f"渲染已停止: {self.script_path}")
                    return

                line = self.process.stdout.readline()
                if line == '' and self.process.poll() is not None:
                    break
                if line:
                    logging.debug(line.strip())
                    frame_match = re.search(r'Rendering frame (\d+)', line)
                    if frame_match:
                        current_frame = int(frame_match.group(1))
                        progress = int((current_frame - self.start_frame + 1) / total_frames * 100)
                    else:
                        # 模拟进度
                        simulated_progress += 1
                        progress = min(simulated_progress, 100)
                    self.progress.emit(progress)
                time.sleep(0.1)  # 防止CPU过载

            stdout, stderr = self.process.communicate()
            if self.process.returncode == 0:
                self.result.emit(f"渲染成功: {self.script_path}\n{stdout}")
            else:
                logging.error(f"渲染错误 {self.script_path}: {stderr}")
                self.result.emit(f"渲染错误 {self.script_path}: {stderr}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"发生异常: {e}")
            self.result.emit(f"渲染错误 {self.script_path}: {e}")
        finally:
            if not self._is_stopped:  # 只有正常渲染完成时才设置为100%
                self.progress.emit(100)
            self.finished_signal.emit(self.row_index)

    def stop(self):
        self._is_stopped = True
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)  # 等待5秒，如果进程没有在5秒内终止，强制杀死
                if self.process.poll() is None:  # 如果进程还在运行
                    self.process.kill()
            except Exception as e:
                logging.error(f"尝试终止渲染进程时发生错误: {e}")
            finally:
                if self.process:
                    self.process = None
        self.quit()  # 确保线程也停止
        self.wait()  # 等待线程结束

class NukeBatchRenderTool(QWidget):
    """
    A tool for batch rendering Nuke scripts with a GUI interface.
    """

    def __init__(self):
        """
        Initialize the NukeBatchRenderTool with UI setup and initial configurations.
        """
        super().__init__()
        self.initUI()
        self.nk_files = {}  # 使用字典存储Nuke脚本信息
        self.threads = []  # 渲染线程列表
        self.current_script_index = 0  # 当前脚本索引
        self.parallel_rendering_enabled = False  # 是否启用并行渲染
        self.nuke_path = self.get_nuke_path()  # 自动检测Nuke路径
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)  # 使用线程池
        self.render_queue = deque()  # 使用deque来管理渲染队列

    def initUI(self):
        """
        Set up the user interface for the batch rendering tool.
        """
        self.setWindowTitle('Nuke 批量渲染工具')
        self.setGeometry(300, 300, 800, 700)

        layout = QGridLayout()

        # Nuke版本选择
        self.nuke_version_combo = QComboBox(self)
        self.nuke_version_combo.addItems(["Nuke13.0v4", "Nuke15.1v3"])
        self.nuke_version_combo.currentIndexChanged.connect(self.update_nuke_path)
        layout.addWidget(QLabel('选择Nuke版本：'), 0, 0)
        layout.addWidget(self.nuke_version_combo, 0, 1)

        # Nuke路径输入
        self.nuke_path_input = QLineEdit(self)
        self.nuke_path_input.setPlaceholderText("或将NukeX可执行文件拖放至此")
        self.nuke_path_input.textChanged.connect(self.update_nuke_path)
        layout.addWidget(self.nuke_path_input, 1, 0, 1, 2)

        self.setAcceptDrops(True)

        # 文件选择按钮
        self.select_files_btn = QPushButton('选择Nuke脚本 (.nk)', self)
        self.select_files_btn.clicked.connect(self.select_nk_files)
        layout.addWidget(self.select_files_btn, 2, 0, 1, 2)

        # 文件表格
        self.file_table = QTableWidget(self)
        self.file_table.setColumnCount(8)
        self.file_table.setHorizontalHeaderLabels(
            ['文件路径', '开始帧', '结束帧', '渲染节点', '输出目录', '进度', '', '停止']
        )
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.file_table, 3, 0, 1, 3)

        # 渲染按钮
        self.render_btn = QPushButton('开始渲染', self)
        self.render_btn.clicked.connect(self.start_rendering)
        layout.addWidget(self.render_btn, 4, 0, 1, 3)

        # 并行渲染复选框
        self.parallel_render_checkbox = QCheckBox('启用并行渲染', self)
        self.parallel_render_checkbox.stateChanged.connect(self.toggle_parallel_rendering)
        layout.addWidget(self.parallel_render_checkbox, 5, 0, 1, 2)

        # 作者信息
        author_info = QLabel("微信公众号：Nuke学习社\nQQ交流群：979658080", self)
        layout.addWidget(author_info, 6, 0, 1, 3)

        # 帮助按钮
        self.help_btn = QPushButton('帮助 / 使用说明', self)
        self.help_btn.clicked.connect(self.show_help)
        layout.addWidget(self.help_btn, 7, 0, 1, 3)

        # 日志输出窗口
        self.log_output = QTextEdit(self)
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output, 8, 0, 1, 3)

        # 状态标签
        self.status_label = QLabel("状态：准备就绪", self)
        layout.addWidget(self.status_label, 9, 0, 1, 3)

        self.setLayout(layout)

    @lru_cache(maxsize=None)
    def get_nuke_path(self):
        """
        Detect the Nuke executable path based on the operating system.
        """
        if sys.platform == "win32":
            return self.detect_nuke_windows()
        elif sys.platform == "linux":
            return self.detect_nuke_linux()
        return ""

    @lru_cache(maxsize=None)
    def detect_nuke_windows(self):
        """
        Detect installed Nuke versions on Windows by checking the registry.
        """
        nuke_versions = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Foundry\Nuke") as registry_key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        version_path = os.path.join(r"SOFTWARE\WOW6432Node\Foundry\Nuke", subkey_name)
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, version_path) as version_key:
                            nuke_path, _ = winreg.QueryValueEx(version_key, "InstallLocation")
                            nuke_versions.append(nuke_path)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        return nuke_versions[0] if nuke_versions else ""

    @lru_cache(maxsize=None)
    def detect_nuke_linux(self):
        """
        Check common installation paths for Nuke on Linux.
        """
        possible_paths = [
            "/usr/local/Nuke12.0v5/Nuke",
            "/usr/local/Nuke13.0v4/Nuke",
            "/opt/Foundry/Nuke12.0v5/Nuke",
        ]
        return next((path for path in possible_paths if os.path.exists(path)), "")

    def update_nuke_path(self):
        """
        Update the Nuke path based on the selected version or user input.
        """
        try:
            selected_version = self.nuke_version_combo.currentText()
            if selected_version in NUKE_PATHS:
                self.nuke_path = NUKE_PATHS[selected_version]
            else:
                self.nuke_path = self.nuke_path_input.text()
            if not os.path.exists(self.nuke_path):
                raise FileNotFoundError(f"未找到Nuke可执行文件: {self.nuke_path}")
            self.nuke_path_input.setText(self.nuke_path)
        except Exception as e:
            logging.error(f"更新Nuke路径时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"更新Nuke路径时发生错误: {e}")

    def select_files(self):
        """
        Open a file dialog to select Nuke script files.
        """
        try:
            files, _ = QFileDialog.getOpenFileNames(self, '选择Nuke脚本', '', 'Nuke脚本 (*.nk)')
            return files
        except Exception as e:
            logging.error(f"文件选择错误: {e}")
            QMessageBox.critical(self, "错误", f"选择文件时发生错误: {e}")
            return []

    def select_nk_files(self):
        """
        Handle file selection and update the file table.
        """
        try:
            files = self.select_files()
            existing_files = set(self.nk_files.keys())
            for file_path in files:
                if file_path not in existing_files:
                    self.nk_files[file_path] = {
                        'start_frame': 1,
                        'end_frame': 100,
                        'render_node': 'Render1',
                        'output_directory': '',
                        'progress': 0
                    }
                    existing_files.add(file_path)
            self.update_file_table()
        except Exception as e:
            logging.error(f"文件选择错误: {e}")
            QMessageBox.critical(self, "错误", f"选择文件时发生错误: {e}")

    def update_file_table(self):
        """
        Update the table widget with the selected Nuke scripts and their settings.
        """
        try:
            self.file_table.setRowCount(len(self.nk_files))
            for row, (file_path, info) in enumerate(self.nk_files.items()):
                if not os.path.exists(file_path):
                    continue
                self.file_table.setItem(row, 0, QTableWidgetItem(file_path))

                start_frame_spinbox = self.create_spinbox(info['start_frame'])
                self.file_table.setCellWidget(row, 1, start_frame_spinbox)

                end_frame_spinbox = self.create_spinbox(info['end_frame'])
                self.file_table.setCellWidget(row, 2, end_frame_spinbox)

                render_node_combo = QComboBox()
                render_node_combo.addItems(['Render1', 'Render2', 'Render3'])
                render_node_combo.setCurrentText(info['render_node'])
                self.file_table.setCellWidget(row, 3, render_node_combo)

                output_directory_btn = QPushButton('选择输出目录')
                output_directory_btn.clicked.connect(lambda _, r=row: self.select_output_directory(r))
                self.file_table.setCellWidget(row, 4, output_directory_btn)

                progress_bar = QProgressBar()
                progress_bar.setValue(info['progress'])
                self.file_table.setCellWidget(row, 5, progress_bar)

                delete_btn = QToolButton()
                delete_btn.setText('删除')
                delete_btn.clicked.connect(lambda _, r=row: self.remove_script_by_row(r))
                self.file_table.setCellWidget(row, 6, delete_btn)

                stop_btn = QToolButton()
                stop_btn.setText('停止')
                stop_btn.clicked.connect(lambda _, r=row: self.stop_render_thread(r))
                self.file_table.setCellWidget(row, 7, stop_btn)
        except Exception as e:
            logging.error(f"更新文件表格时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"更新文件表格时发生错误: {e}")

    def create_spinbox(self, value):
        """
        Create a QSpinBox widget with a specified initial value.
        """
        spinbox = QSpinBox()
        spinbox.setRange(1, 100000)
        spinbox.setValue(value)
        return spinbox

    def dragEnterEvent(self, event):
        """
        Handle drag enter events to accept file drops.
        """
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        """
        Handle file drop events to add Nuke scripts to the list.
        """
        try:
            files = event.mimeData().urls()
            existing_files = set(self.nk_files.keys())
            for file in files:
                file_path = file.toLocalFile()
                if file_path.endswith('.nk') and file_path not in existing_files:
                    self.nk_files[file_path] = {
                        'start_frame': 1,
                        'end_frame': 100,
                        'render_node': 'Render1',
                        'output_directory': '',
                        'progress': 0
                    }
                    existing_files.add(file_path)
            self.update_file_table()
        except Exception as e:
            logging.error(f"拖放文件时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"拖放文件时发生错误: {e}")

    def show_context_menu(self, pos):
        """
        Show a context menu when right-clicking on the table.
        """
        try:
            context_menu = QMenu(self)
            remove_action = context_menu.addAction("删除脚本")
            action = context_menu.exec_(self.file_table.viewport().mapToGlobal(pos))
            if action == remove_action:
                self.remove_selected_script()
        except Exception as e:
            logging.error(f"显示上下文菜单时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"显示上下文菜单时发生错误: {e}")

    def remove_selected_script(self):
        """
        Remove the selected script from the table and the list of files.
        """
        try:
            for row in sorted(self.file_table.selectionModel().selectedRows(), reverse=True):
                file_path = self.file_table.item(row.row(), 0).text()
                del self.nk_files[file_path]
                self.file_table.removeRow(row.row())
        except Exception as e:
            logging.error(f"删除选中的脚本时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"删除选中的脚本时发生错误: {e}")

    def remove_script_by_row(self, row):
        """
        Remove a script by its row index from the table and the list of files.
        """
        try:
            file_path = self.file_table.item(row, 0).text()
            del self.nk_files[file_path]
            self.file_table.removeRow(row)
        except Exception as e:
            logging.error(f"按行索引删除脚本时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"按行索引删除脚本时发生错误: {e}")

    def toggle_parallel_rendering(self, state):
        """
        Toggle parallel rendering mode.
        """
        try:
            self.parallel_rendering_enabled = state == Qt.Checked
            logging.debug(f"并行渲染启用: {self.parallel_rendering_enabled}")
        except Exception as e:
            logging.error(f"切换并行渲染模式时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"切换并行渲染模式时发生错误: {e}")

    def start_rendering(self):
        """
        Start the rendering process for selected Nuke scripts.
        """
        try:
            if not os.path.exists(self.nuke_path):
                raise FileNotFoundError(f"未找到Nuke可执行文件: {self.nuke_path}")
            if not self.nk_files:
                raise ValueError("未选择任何Nuke脚本进行渲染。")

            self.current_script_index = 0
            self.status_label.setText("状态：渲染开始...")
            logging.info("开始渲染过程。")
            QMessageBox.information(self, "渲染开始", "渲染过程已经开始。")
            self.render_queue = deque(self.nk_files.items())
            self.start_next_render()
        except (FileNotFoundError, ValueError) as e:
            logging.error(f"渲染启动错误: {e}")
            QMessageBox.critical(self, "错误", str(e))
        except Exception as e:
            logging.error(f"未知错误: {e}")
            QMessageBox.critical(self, "错误", f"发生未知错误: {e}")

    def start_next_render(self):
        """
        Start rendering for the next script in sequence.
        """
        try:
            if not self.render_queue:
                logging.info("所有脚本渲染完成。")
                self.status_label.setText("状态：渲染完成")
                QMessageBox.information(self, "渲染完成", "所有脚本渲染成功！")
                return
            file_path, info = self.render_queue.popleft()
            self.start_render_thread(file_path, info)
        except Exception as e:
            logging.error(f"启动下一个渲染时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"启动下一个渲染时发生错误: {e}")

    def start_render_thread(self, file_path, info):
        """
        Start a rendering thread for a specific script.
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Nuke脚本未找到: {file_path}")

            row = list(self.nk_files.keys()).index(file_path)
            progress_bar = self.file_table.cellWidget(row, 5)
            thread = RenderThread(self.nuke_path, file_path, info['start_frame'], info['end_frame'], info['render_node'], row)
            thread.progress.connect(progress_bar.setValue)
            thread.result.connect(self.handle_render_result)
            thread.finished_signal.connect(lambda r=row: self.on_render_finished(r))
            self.threads.append(thread)
            logging.debug(f"开始渲染线程，行 {row}")
            future = self.executor.submit(thread.run)
            # 可以在这里添加回调函数来处理渲染结果
        except Exception as e:
            logging.error(f"启动渲染线程时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"启动渲染线程时发生错误: {e}")

    def stop_render_thread(self, row):
        """
        Stop the rendering thread for a specific row.
        """
        try:
            if row < len(self.threads) and self.threads[row].isRunning():
                self.threads[row].stop()  # 调用stop方法来停止渲染
                # 取消线程池中的任务
                for future in self.executor._futures.values():
                    future.cancel()
                logging.info(f"渲染已停止，行 {row}")
                self.status_label.setText(f"状态：渲染已停止，行 {row}")
        except Exception as e:
            logging.error(f"停止渲染线程时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"停止渲染线程时发生错误: {e}")

    def on_render_finished(self, row):
        """
        Handle the completion of a render thread.
        """
        try:
            logging.info(f"渲染完成，行 {row}")
            # 使用QMetaObject.invokeMethod来确保UI更新在主线程中进行
            QMetaObject.invokeMethod(self, "update_ui_on_render_finished", Qt.QueuedConnection, Q_ARG(int, row))
        except Exception as e:
            logging.error(f"渲染完成处理时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"渲染完成处理时发生错误: {e}")

    def update_ui_on_render_finished(self, row):
        try:
            self.status_label.setText(f"状态：渲染完成，行 {row}")
            QMessageBox.information(self, "渲染完成", f"脚本 {list(self.nk_files.keys())[row]} 渲染完成！")
            self.current_script_index += 1
            self.start_next_render()
        except Exception as e:
            logging.error(f"更新UI时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"更新UI时发生错误: {e}")

    def handle_render_result(self, message):
        """
        Handle rendering results and update the UI.
        """
        try:
            logging.info(message)
            self.log_output.append(message)
            self.status_label.setText("状态： " + message.splitlines()[0])
        except Exception as e:
            logging.error(f"处理渲染结果时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"处理渲染结果时发生错误: {e}")

    def show_help(self):
        """
        Display help information for using the tool.
        """
        try:
            help_message = (
                "使用说明:\n"
                "1. 选择Nuke版本或拖拽NukeX可执行文件到输入框。\n"
                "2. 点击'选择Nuke脚本'按钮选择要渲染的.nk文件。\n"
                "3. 在表格中设置每个脚本的开始和结束帧，以及渲染节点。\n"
                "4. 可选择并行渲染。\n"
                "5. 点击'开始渲染'按钮开始批量渲染。\n"
                "6. 点击表格中对应的'Stop'按钮可以停止当前渲染。\n"
            )
            QMessageBox.information(self, "帮助 / 使用说明", help_message)
        except Exception as e:
            logging.error(f"显示帮助信息时发生错误: {e}")
            QMessageBox.critical(self, "错误", f"显示帮助信息时发生错误: {e}")

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        ex = NukeBatchRenderTool()
        ex.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"程序启动错误: {e}")
        QMessageBox.critical(None, "错误", f"程序启动时发生错误: {e}")
