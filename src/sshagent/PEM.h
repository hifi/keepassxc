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

#ifndef PEM_H
#define PEM_H

#include "OpenSSHKey.h"
#include <QtCore>

namespace SSHAgent {
    class PEM;
}

class PEM
{
public:
    PEM(QIODevice& dev) : PEM(dev.readAll()) { }
    PEM(QByteArray& ba) : PEM(QString::fromUtf8(ba)) { }
    PEM(QString s) : m_string(s) { }

    bool parse();
    QString getType();
    QList<QSharedPointer<OpenSSHKey>> getKeys(const QString &passphrase = nullptr);

private:
    QString m_string;
    QString m_type;
    QByteArray m_data;
};

#endif // PEM_H
