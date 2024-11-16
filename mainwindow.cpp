#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "lic_manager.hpp"
#include <QFileDialog>
#include <QMimeData>
#include <QFileInfo>
#include <QMessageBox>
#include <QFuture>
#include <QFutureWatcher>
#include <QtConcurrent>
#include <QClipboard>
#include <regex>

typedef std::tuple<bool, std::string, std::string> KeyResult;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setFixedSize(size());
    pat = new Patcher;
    connect(pat, &Patcher::postErrMsg, this, [&](const QString &msg)
            { QMessageBox::critical(this, "Error", msg, QMessageBox::Button::Ok); });
    connect(ui->btnSelect, &QPushButton::clicked, this, &MainWindow::onSelectFileDlg);
    connect(ui->sliderQuant, &QSlider::valueChanged, this, [&](int value)
            { ui->labelQuant->setText(QString::number(value)); });
    connect(ui->btnPatch, &QPushButton::clicked, this, &MainWindow::onPatch);
    connect(ui->btnGenKey, &QPushButton::clicked, this, &MainWindow::onGenKey);
    connect(ui->btnCopy, &QPushButton::clicked, this, &MainWindow::onCopy);
    connect(ui->btnExit, &QPushButton::clicked, this, &MainWindow::close);
    // Rellenar valor por defecto
    ui->edtUserName->setText("Perro");
    ui->edtCompName->setText("LaJodidaEmpresa");
    ui->edtSerial->setText("Aceg-2345");
    ui->sliderQuant->setValue(999);
}

MainWindow::~MainWindow()
{
    delete pat;
    delete ui;
}

void MainWindow::onSelectFileDlg()
{
    QString filePath = QFileDialog::getOpenFileName(
        nullptr, "Select an Executable File", "", "Executable Files (*.exe)");
    if (!filePath.isEmpty())
        ui->textExePath->setText(filePath);
}

void MainWindow::onCopy()
{
    QString plainText = ui->textKey->toPlainText();
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText(plainText, QClipboard::Clipboard);
}

void MainWindow::onGenKey()
{
    std::regex pattern("^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$");
    std::string serial = ui->edtSerial->text().toStdString();
    std::string username = ui->edtUserName->text().toStdString();
    std::string company = ui->edtCompName->text().toStdString();
    int num = ui->sliderQuant->value();
    if (!std::regex_match(serial, pattern))
    {
        QMessageBox::warning(this, "Warning", "Serial pattern is invalid! "
                                              "Make sure it complies with XXXX-XXXX, where X is a digital, lowercase and uppercase letter.");
        return;
    }
    ui->edtCompName->setEnabled(false);
    ui->edtSerial->setEnabled(false);
    ui->edtUserName->setEnabled(false);
    ui->sliderQuant->setEnabled(false);
    ui->btnGenKey->setEnabled(false);
    QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
    QFuture<KeyResult> future = QtConcurrent::run(
        [username, company, num, serial]() -> KeyResult
        {
            try
            {
                LicenseEncoder encoder(username, company, num, serial);
                std::string key = encoder.encode();
                LicenseDecoder decoder(key);
                auto [decodedNum, atsite, version, rand, serialNum, decodedUsername] = decoder.decode();
                std::string testResult = "Version: " + version + "\n";
                testResult += "Serial: " + serialNum + "\n";
                testResult += "User Name: " + decodedUsername + "\n";
                testResult += "Company: " + atsite + "\n";
                testResult += "Max Users: " + std::to_string(decodedNum) + "\n";
                testResult += "Random Num: " + rand;
                return make_tuple(true, key, testResult);
            }
            catch (const std::exception &e)
            {
                return make_tuple(false, std::string(e.what()), "");
            }
        });
    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<void>::finished, this, [this, watcher]()
            {
                ui->edtCompName->setEnabled(true);
                ui->edtSerial->setEnabled(true);
                ui->edtUserName->setEnabled(true);
                ui->sliderQuant->setEnabled(true);
                ui->btnGenKey->setEnabled(true);
                auto [suc, key, testResult] = watcher->result();
                if(suc) {
                    ui->textKey->setText(QString::fromStdString(key));
                    QMessageBox::information(this, "OK", "Key generation completed and the test has been passed!\n" +
                                                             QString::fromStdString(testResult), QMessageBox::Button::Ok);
                } else {
                    QMessageBox::critical(this, "Error", QString::fromStdString(key), QMessageBox::Button::Ok);
                }
                watcher->deleteLater(); 
            });
}

void MainWindow::onPatch()
{
    QString path = ui->textExePath->toPlainText();
    if (path.isEmpty() || !QFile(path).exists())
    {
        QMessageBox::warning(this, "Warning", "Please provide a valid file path by selection or dropping!");
        return;
    }
    ui->btnPatch->setEnabled(false);
    ui->btnSelect->setEnabled(false);
    setAcceptDrops(false);
    QFutureWatcher<bool> *watcher = new QFutureWatcher<bool>(this);
    QFuture<bool> future = QtConcurrent::run([this, path]() -> bool
        {
            bool suc1 = this->pat->loadFile(path);
            if(suc1) {
                bool suc2 = this->pat->patchFile();
                if(suc2) return this->pat->saveFile(path);
            }
            return false; 
        });
    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<void>::finished, this, [this, watcher]()
            {
                ui->btnPatch->setEnabled(true);
                ui->btnSelect->setEnabled(true);
                setAcceptDrops(true);
                if(watcher->result()) QMessageBox::information(this, "OK", "The file has been successfully patched!");
                watcher->deleteLater(); 
            });
}

QString getExecutableFileType(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }

    QByteArray header = file.read(16); // Leer los 16 primeros bytes
    file.close();

    if (header.startsWith("\x4D\x5A")) { // Encabezamiento MZ para Windows PE
        return "Windows PE";
    }
    else if (header.startsWith("\x7F\x45\x4C\x46")) { // Encabezamiento ELF para Linux
        return "Linux ELF";
    }
    else if (header.startsWith("\xCF\xFA\xED\xFE") || header.startsWith("\xCE\xFA\xED\xFE")) { // Encabezamiento Mach-O para MacOS
        return "MacOS Mach-O";
    }
    else if (header.startsWith("\x7F\xAD\xA0\xDE")) { // Ejecutables FreeBSD
        return "FreeBSD ELF";
    }
    else {
        return QString();
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls() && event->mimeData()->urls().size() == 1) {
        QString filePath = event->mimeData()->urls().first().toLocalFile();
        QFileInfo fileInfo(filePath);

        if (fileInfo.isFile()) {
            QString fileType = getExecutableFileType(filePath);
            if (!fileType.isEmpty()) {
                event->acceptProposedAction();
                return;
            }
        }
    }
    event->ignore();
}

void MainWindow::dropEvent(QDropEvent* event)
{
    if (event->mimeData()->hasUrls() && event->mimeData()->urls().size() == 1) {
        QString filePath = event->mimeData()->urls().first().toLocalFile();
        if (!filePath.isEmpty())
            ui->textExePath->setText(filePath);
    }
}
