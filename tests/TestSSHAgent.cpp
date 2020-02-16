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
                                      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAfwAAACJzay1lY2\n"
                                      "RzYS1zaGEyLW5pc3RwMjU2QG9wZW5zc2guY29tAAAACG5pc3RwMjU2AAAAQQQ2Pr1d6zUa\n"
                                      "qcmYgjTGQUF9QPkFEo2Q7aQbvyL/0KL9FObuOfzqxs8mDqswXEsXR4g5L6P7vEe6nPqzSW\n"
                                      "X9/jJfAAAABHNzaDoAAAD4kyJ795Mie/cAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBv\n"
                                      "cGVuc3NoLmNvbQAAAAhuaXN0cDI1NgAAAEEENj69Xes1GqnJmII0xkFBfUD5BRKNkO2kG7\n"
                                      "8i/9Ci/RTm7jn86sbPJg6rMFxLF0eIOS+j+7xHupz6s0ll/f4yXwAAAARzc2g6AQAAAEA4\n"
                                      "Dbqd2ub7R1QQRm8nBZWDGJSiNIh58vvJ4EuAh0FnJsRvvASsSDiGuuXqh56wT5xmlnYvbb\n"
                                      "nLWO4/1+Mp5PaDAAAAAAAAACJvcGVuc3Noa2V5LXRlc3QtZWNkc2Etc2tAa2VlcGFzc3hj\n"
                                      "AQI=\n"
                                      "-----END OPENSSH PRIVATE KEY-----\n");

    const QByteArray keyData = keyString.toLatin1();

    OpenSSHKey key;
    key.parsePKCS1PEM(keyData);
    QCOMPARE(key.errorString(), QString(""));
    QVERIFY(!key.encrypted());
    QCOMPARE(key.cipherName(), QString("none"));
    QCOMPARE(key.type(), QString("sk-ecdsa-sha2-nistp256@openssh.com"));
    QCOMPARE(key.comment(), QString("opensshkey-test-ecdsa-sk@keepassxc"));
    QCOMPARE(key.fingerprint(), QString("SHA256:ctOtAsPMqbtumGI41o2oeWfGDah4m1ACILRj+x0gx0E"));

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
