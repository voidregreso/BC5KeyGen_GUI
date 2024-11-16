#ifndef PATCHER_H
#define PATCHER_H

#include <QVector>
#include <QString>
#include <QByteArray>
#include <QObject>

class Patcher : public QObject {
    Q_OBJECT
public:
    bool loadFile(const QString &filename);
    bool saveFile(const QString &filename);
    bool patchFile();
    Patcher() = default;
    ~Patcher() = default;
signals:
    void postErrMsg(const QString &msg);
private:
    QVector<char> fileContent;
    const QByteArray target_str = "++11Ik:7EFlNLs6Yqc3p-LtUOXBElimekQm8e3BTSeGhxhlpmVDeVVrrUAkLTXpZ7mK6jAPAOhyHiokPtYfmokklPELfOxt1s5HJmAnl-5r8YEvsQXY8-dm6EFwYJlXgWOCutNn2+FsvA7EXvM-2xZ1MW8LiGeYuXCA6Yt2wTuU4YWM+ZUBkIGEs1QRNRYIeGB9GB9YsS8U2-Z3uunZPgnA5pF+E8BRwYz9ZE--VFeKCPamspG7tdvjA3AJNRNrCVmJvwq5SqgEQwINdcmwwjmc4JetVK76og5A5sPOIXSwOjlYK+Sm8rvlJZoxh0XFfyioHz48JV3vXbBKjgAlPAc7Np1+wk";
};

#endif // PATCHER_H
