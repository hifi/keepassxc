/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
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

#include "TestSSHAgent.h"
#include "TestGlobal.h"
#include "core/Config.h"
#include "crypto/Crypto.h"
#include "sshagent/SSHAgent.h"

QTEST_GUILESS_MAIN(TestSSHAgent)

void TestSSHAgent::initTestCase()
{
    QVERIFY(Crypto::init());
    Config::createTempFileInstance();

    m_agentSocketFile.setAutoRemove(true);
    QVERIFY(m_agentSocketFile.open());

    m_agentSocketFileName = m_agentSocketFile.fileName();
    QVERIFY(!m_agentSocketFileName.isEmpty());

    // let ssh-agent re-create it as a socket
    QVERIFY(m_agentSocketFile.remove());

    QStringList arguments;
    arguments << "-D"
              << "-a" << m_agentSocketFileName;

    QElapsedTimer timer;
    timer.start();

    qDebug() << "ssh-agent starting with arguments" << arguments;
    m_agentProcess.setProcessChannelMode(QProcess::ForwardedChannels);
    m_agentProcess.start("ssh-agent", arguments);
    m_agentProcess.closeWriteChannel();

    if (!m_agentProcess.waitForStarted()) {
        QFAIL("ssh-agent could not be started");
    }

    qDebug() << "ssh-agent started as pid" << m_agentProcess.pid();

    // we need to wait for the agent to open the socket before going into real tests
    QFileInfo socketFileInfo(m_agentSocketFileName);
    while (!timer.hasExpired(2000)) {
        if (socketFileInfo.exists()) {
            break;
        }
        QThread::msleep(10);
    }

    QVERIFY(socketFileInfo.exists());
    qDebug() << "ssh-agent initialized in" << timer.elapsed() << "ms";
}

void TestSSHAgent::testConfiguration()
{
    SSHAgent agent;

    // default config must not enable agent
    QVERIFY(!agent.isEnabled());

    agent.setEnabled(true);
    QVERIFY(agent.isEnabled());

    // this will either be an empty string or the real ssh-agent socket path, doesn't matter
    QString defaultSocketPath = agent.socketPath(false);

    // overridden path must match default before setting an override
    QCOMPARE(agent.socketPath(true), defaultSocketPath);

    agent.setAuthSockOverride(m_agentSocketFileName);

    // overridden path must match what we set
    QCOMPARE(agent.socketPath(true), m_agentSocketFileName);

    // non-overridden path must match the default
    QCOMPARE(agent.socketPath(false), defaultSocketPath);
}

void TestSSHAgent::testIdentity()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());
    QVERIFY(agent.testConnection());

    const QString keyString = QString("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                                      "QyNTUxOQAAACDdlO5F2kF2WzedrBAHBi9wBHeISzXZ0IuIqrp0EzeazAAAAKjgCfj94An4\n"
                                      "/QAAAAtzc2gtZWQyNTUxOQAAACDdlO5F2kF2WzedrBAHBi9wBHeISzXZ0IuIqrp0EzeazA\n"
                                      "AAAEBe1iilZFho8ZGAliiSj5URvFtGrgvmnEKdiLZow5hOR92U7kXaQXZbN52sEAcGL3AE\n"
                                      "d4hLNdnQi4iqunQTN5rMAAAAH29wZW5zc2hrZXktdGVzdC1wYXJzZUBrZWVwYXNzeGMBAg\n"
                                      "MEBQY=\n"
                                      "-----END OPENSSH PRIVATE KEY-----\n");

    const QByteArray keyData = keyString.toLatin1();

    OpenSSHKey key;
    QVERIFY(key.parsePKCS1PEM(keyData));

    KeeAgentSettings settings;
    bool keyInAgent;

    // test adding a key works
    QVERIFY(agent.addIdentity(key, settings));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && keyInAgent);

    // test removing a key works
    QVERIFY(agent.removeIdentity(key));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && !keyInAgent);

    // test disabling agent will remove keys which have remove-on-lock set
    settings.setRemoveAtDatabaseClose(true);
    QVERIFY(agent.addIdentity(key, settings));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && keyInAgent);
    agent.setEnabled(false);
    QVERIFY(agent.checkIdentity(key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::cleanupTestCase()
{
    if (m_agentProcess.state() != QProcess::NotRunning) {
        qDebug() << "Killing ssh-agent pid" << m_agentProcess.pid();
        m_agentProcess.terminate();
        m_agentProcess.waitForFinished();
    }

    m_agentSocketFile.remove();
}
