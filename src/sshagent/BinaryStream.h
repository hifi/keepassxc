/*
 *  Copyright (C) 2017 Toni Spets <toni.spets@iki.fi>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BINARYSTREAM_H
#define BINARYSTREAM_H

#include <QObject>
#include <QIODevice>
#include <QBuffer>

class BinaryStream : public QObject
{
    Q_OBJECT
public:
    explicit BinaryStream(QObject *parent = 0) : QObject(parent) { }
    BinaryStream(QIODevice *dev, QObject *parent = 0) : QObject(parent), m_dev(dev) { }
    BinaryStream(QByteArray *ba, QObject *parent = 0);
    ~BinaryStream();

    const QString errorString();
    QIODevice* getDevice();
    void setDevice(QIODevice *dev);
    void setData(QByteArray *ba);
    void setTimeout(int timeout);

    bool read(QByteArray &ba);
    bool read(quint32 &i);
    bool read(quint16 &i);
    bool read(quint8 &i);
    bool readPack(QByteArray &ba);
    bool readPack(QString &str);

    bool write(const QByteArray &ba);
    bool write(quint32 i);
    bool write(quint8 i);
    bool writePack(const QByteArray &ba);
    bool writePack(const QString &s);
    bool writePack(quint8 i);

    bool flush();

signals:

public slots:

protected:
    bool read(char *ptr, qint64 len);
    bool write(const char *ptr, qint64 len);

private:
    int m_timeout = -1;
    QString m_error;
    QIODevice *m_dev = 0;
    QBuffer *m_buffer = 0;
};

#endif // BINARYSTREAM_H
