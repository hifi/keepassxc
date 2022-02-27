/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
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

#include "SyncCommand.h"
#include "core/Entry.h"

#include <QCommandLineParser>

#include <QDebug>

SyncCommand::SyncCommand(QObject *parent)
    : QProcess(parent)
    , m_stdin()
    , m_stdout()
    , m_stderr()
{
    connect(this, &QProcess::started, this, [this]() { inputBytesWritten(0); });
    connect(this, &QProcess::bytesWritten, this, &SyncCommand::inputBytesWritten);
    connect(this, &QProcess::readyReadStandardOutput, this, &SyncCommand::processStandardOutput);
    connect(this, &QProcess::readyReadStandardError, this, &SyncCommand::processStandardError);

    // FIXME: these are unlimited size
    m_stdout.open(QIODevice::WriteOnly);
    m_stderr.open(QIODevice::WriteOnly);

    // FIXME: create a tempfile name for {DATABASE_PATH} for merge
    // FIXME: remove temp file when command is destructed? who controls it?
}

void SyncCommand::inputBytesWritten(qint64 bytes)
{
    // advance stdin buffer as much as was written
    m_stdin.skip(bytes);

    // EOF the stdin stream when our input is read out
    if (m_stdin.atEnd()) {
        closeWriteChannel();
    } else {
        // FIXME: do we need to define this somewhere?
        static char data[4096];
        int npeeked;
        // peek up to buffer size from input
        if ((npeeked = m_stdin.peek(data, sizeof(data))) > 0) {
            // try to write as much as we peeked, we'll get called again for the results
            write(data, npeeked);
        }
    }
}

void SyncCommand::setInString(const QString& input)
{
    m_stdin.setData(input.toUtf8());
    m_stdin.open(QIODevice::ReadOnly);
}

void SyncCommand::processStandardOutput()
{
    m_stdout.buffer() += readAllStandardOutput();
}

void SyncCommand::processStandardError()
{
    m_stderr.buffer() += readAllStandardError();
}

QString SyncCommand::outString()
{
    return QString(m_stdout.buffer());
}

QString SyncCommand::errString()
{
    return QString(m_stderr.buffer());
}

void SyncCommand::fromTemplate(const QString& command, const QString& input, Database* database)
{
    Q_UNUSED(database);

    // FIXME: make default shell a global setting (/bin/sh on non-Windows, cmd.exe on Windows)
    // or write a simple one command shell parser?
    setProgram("/bin/sh");
    setArguments(QStringList() << "-c" << resolveMultiplePlaceholdersRecursive(command, 5, database));
    setInString(resolveMultiplePlaceholdersRecursive(input, 5, database));
}

QString SyncCommand::resolvePlaceholder(const QString& placeholder, Database* database) const
{
    if (placeholder.startsWith(QLatin1Literal("{REF:"))) {
        return Entry::resolveReferencePlaceholderRecursive(placeholder, 5, database);
    }
    qDebug() << placeholder;
    return placeholder;
}

QString SyncCommand::resolveMultiplePlaceholdersRecursive(const QString& str, int maxDepth, Database* database) const
{
    if (maxDepth <= 0) {
        qWarning("Maximum depth of replacement has been reached.");
        return str;
    }

    QString result = str;
    QRegExp placeholderRegEx("(\\{[^\\}]+\\})", Qt::CaseInsensitive, QRegExp::RegExp2);
    placeholderRegEx.setMinimal(true);
    int pos = 0;
    while ((pos = placeholderRegEx.indexIn(str, pos)) != -1) {
        const QString found = placeholderRegEx.cap(1);
        result.replace(found, resolvePlaceholder(found, database));
        pos += placeholderRegEx.matchedLength();
    }

    if (result != str) {
        result = resolveMultiplePlaceholdersRecursive(result, maxDepth - 1, database);
    }

    return result;
}
