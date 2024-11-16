#include "patcher.h"
#include <QFile>

bool Patcher::loadFile(const QString &filename) {
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly)) {
        emit postErrMsg("Error opening file: " + filename);
        return false;
    }
    // Leer todo el contenido del archivo en el búfer
    QByteArray byteArray = file.readAll();
    fileContent = QVector<char>(byteArray.begin(), byteArray.end());
    return true;
}

bool Patcher::saveFile(const QString &filename) {
    QFile file(filename);

    // Comprobar si el archivo es de sólo lectura
    if (file.exists() && !file.permissions().testFlag(QFileDevice::WriteUser)) {
        // If so, remove it!
        if (!file.setPermissions(file.permissions() | QFileDevice::WriteUser)) {
            emit postErrMsg("Failed to remove read-only attribute: " + filename);
            return false;
        }
    }

    if (!file.open(QIODevice::WriteOnly)) {
        emit postErrMsg("Error writing to file: " + filename);
        return false;
    }

    file.write(fileContent.constData(), fileContent.size());
    return true;
}

bool Patcher::patchFile() {
    QByteArray data(fileContent.constData(), fileContent.size());

    // Encontrar la posición del patrón objetivo
    int pos = data.indexOf(target_str);
    if (pos == -1) {
        emit postErrMsg("Target pattern not found. Check if the file is correct!");
        return false;
    }
    // Modificar el penúltimo carácter
    int modify_pos = pos + target_str.size() - 4;
    if (modify_pos >= 0 && modify_pos < data.size()) {
        data[modify_pos] = 'n';
    } else {
        emit postErrMsg("Position out of bounds. Check if the file is correct!");
        return false;
    }

    // Actualizar datos del búfer
    fileContent = QVector<char>(data.begin(), data.end());
    return true;
}
