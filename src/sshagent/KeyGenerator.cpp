/*
 *  Copyright (C) 2021 KeePassXC Team <team@keepassxc.org>
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

#include "KeyGenerator.h"
#include "OpenSSHKey.h"
#include "BinaryStream.h"
#include "crypto/Random.h"

#include <botan/rsa.h>

#include <QDebug>

namespace KeyGenerator
{
    namespace
    {
        QByteArray encodeBigInt(Botan::BigInt i, int padding = 0)
        {
            QByteArray out(i.bytes() + padding, 0);
            i.binary_encode(reinterpret_cast<uint8_t*>(out.data() + padding), out.size() - padding);
            return out;
        }
    }

    OpenSSHKey generateRSAKey(int bits)
    {
        OpenSSHKey key;

        auto rng = randomGen()->getRng();
        Botan::RSA_PrivateKey rsaKey(*rng, bits);

        QByteArray publicData;
        BinaryStream publicStream(&publicData);

        publicStream.writeString(encodeBigInt(rsaKey.get_e()));
        publicStream.writeString(encodeBigInt(rsaKey.get_n(), 1));

        qDebug() << "modulus";
        qDebug() << rsaKey.get_n().bytes();
        qDebug() << rsaKey.get_n().bits();

        QByteArray privateData;
        BinaryStream privateStream(&privateData);

        privateStream.writeString(encodeBigInt(rsaKey.get_n(), 1));
        privateStream.writeString(encodeBigInt(rsaKey.get_e()));
        privateStream.writeString(encodeBigInt(rsaKey.get_d()));
        privateStream.writeString(encodeBigInt(rsaKey.get_d1()));
        privateStream.writeString(encodeBigInt(rsaKey.get_d2()));
        privateStream.writeString(encodeBigInt(rsaKey.get_p()));
        privateStream.writeString(encodeBigInt(rsaKey.get_q()));

        key.setType("ssh-rsa");
        key.setPublicData(publicData);
        key.setPrivateData(privateData);
        key.setComment("id_rsa");

        return key;
    }
}
