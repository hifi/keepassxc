/*
 *  Copyright (C) 2017 Toni Spets <toni.spets@iki.fi>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_SYNCCOMMAND_H
#define KEEPASSXC_SYNCCOMMAND_H

#include <QProcess>
#include <QBuffer>

class Database;

class SyncCommand : public QProcess
{
public:
    explicit SyncCommand(QObject* parent = nullptr);
    void fromTemplate(const QString& command, const QString& input, Database* database);
    /*
    SyncCommand(const QString& progtam, const QStringList& args const QString& input);
    ~SyncCommand() override = default;
    */
    void setInString(const QString& input);
    QString outString();
    QString errString();
signals:

public slots:
private slots:
    void inputBytesWritten(qint64 bytes);
    void processStandardOutput();
    void processStandardError();

private:
    QString resolvePlaceholder(const QString& placeholder, Database* database) const;
    QString resolveMultiplePlaceholdersRecursive(const QString& str, int maxDepth, Database* database) const;

    QString m_command;
    QStringList m_args;
    QString m_error;

    QBuffer m_stdin;
    QBuffer m_stdout;
    QBuffer m_stderr;
};

#endif // KEEPASSXC_SYNCCOMMAND_H
