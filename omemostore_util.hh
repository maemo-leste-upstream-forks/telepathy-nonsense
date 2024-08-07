
template<typename T>
QXmppTask<T> makeReadyTask(T &&value)
{
    QXmppPromise<T> promise;
    promise.finish(std::move(value));
    return promise.task();
}

inline QXmppTask<void> makeReadyTask()
{
    QXmppPromise<void> promise;
    promise.finish();
    return promise.task();
}

//
// Own device
//

static void
_serializeOwnDevice(QString name, const QXmppOmemoStorage::OwnDevice ownDevice)
{
    QDir dir(_storagePath(name));
    QFile odFile(dir.filePath(QStringLiteral(u"own-device")));

    // TODO: atomic swap
    if (odFile.open(QIODevice::WriteOnly)) {
        qCDebug(qxmppOMEMO) << "serializing own device for: " << name;
        QDataStream out(&odFile);
        out << ownDevice.id
            << ownDevice.label
            << ownDevice.privateIdentityKey
            << ownDevice.publicIdentityKey
            << ownDevice.latestSignedPreKeyId
            << ownDevice.latestPreKeyId;
        odFile.close();
    } else {
        qDebug() << "failed to write-open own device for: " << name;
    }
}

static std::optional<QXmppOmemoStorage::OwnDevice>
_deserializeOwnDevice(QString name)
{
    QDir dir(_storagePath(name));
    QFile odFile(dir.filePath(QStringLiteral(u"own-device")));

    QXmppOmemoStorage::OwnDevice ownDevice;
    if (odFile.open(QIODevice::ReadOnly)) {
        qDebug() << "deserializing own device for: " << name;
        QDataStream in(&odFile);
        in >> ownDevice.id
           >> ownDevice.label
           >> ownDevice.privateIdentityKey
           >> ownDevice.publicIdentityKey
           >> ownDevice.latestSignedPreKeyId
           >> ownDevice.latestPreKeyId;
        odFile.close();
        if (in.status() == QDataStream::Ok)
            return ownDevice;
        qDebug() << "failed to deserialize own-device";
    } else {
        qDebug() << "failed to read-open own device for: " << name;
    }
    return std::nullopt;
}

//
// Signed pre key pairs
//

static void
_serializeSignedPreKeyPairs(QString name,  QHash<uint32_t, QXmppOmemoStorage::SignedPreKeyPair> spkps)
{
    QDir dir(_storagePath(name));
    QFile w(dir.filePath(QStringLiteral(u"spkp")));

    if (w.open(QIODevice::WriteOnly)) {
        QDataStream out(&w);
        for (auto i = spkps.cbegin(), end = spkps.cend(); i != end; ++i) {
            out << i.key()
                << i.value().creationDate
                << i.value().data;
        }
        w.close();
    }
}

static QHash<uint32_t, QXmppOmemoStorage::SignedPreKeyPair>
_deserializeSignedPreKeyPairs(QString name)
{
    QDir dir(_storagePath(name));
    QFile r(dir.filePath(QStringLiteral(u"spkp")));
    QHash<uint32_t, QXmppOmemoStorage::SignedPreKeyPair> spkps;

    if (r.open(QIODevice::ReadOnly)) {
        QDataStream in(&r);
        for (;;) {
            uint32_t key;
            QXmppOmemoStorage::SignedPreKeyPair spkp;
            in >> key
               >> spkp.creationDate
               >> spkp.data;
            if (in.status() != QDataStream::Ok)
                break;
            spkps[key] = spkp;
        }
        r.close();
    }
    return spkps;
}


//
// Pre key pairs
//

static void
_serializePreKeyPairs(QString name, QHash<uint32_t, QByteArray> pkps)
{
    QDir dir(_storagePath(name));
    QFile w(dir.filePath(QStringLiteral(u"pkp")));

    if (w.open(QIODevice::WriteOnly)) {
        QDataStream out(&w);
        for (auto i = pkps.cbegin(), end = pkps.cend(); i != end; ++i) {
            out << i.key()
                << i.value();
        }
        w.close();
    }
}

static QHash<uint32_t, QByteArray>
_deserializePreKeyPairs(QString name)
{
    QDir dir(_storagePath(name));
    QFile r(dir.filePath(QStringLiteral(u"pkp")));
    QHash<uint32_t, QByteArray> pkps;

    if (r.open(QIODevice::ReadOnly)) {
        QDataStream in(&r);
        for (;;) {
            uint32_t key;
            QByteArray value;
            in >> key
               >> value;
            if (in.status() != QDataStream::Ok)
                break;
            pkps[key] = value;
        }
        r.close();
    }
    return pkps;
}

//
// Devices
//
// TODO: could easily flatten to tuple<jid, did> as well

static void
_serializeDevices(QString name, QHash<QString, QHash<uint32_t, QXmppOmemoStorage::Device>> devices)
{
    QDir dir(_storagePath(name));
    QFile w(dir.filePath(QStringLiteral(u"devices")));

    if (w.open(QIODevice::WriteOnly)) {
        QDataStream out(&w);
        for (auto i = devices.cbegin(), end = devices.cend(); i != end; ++i) {
            out << i.key();
            auto jidDevices = i.value();
            for (auto i = jidDevices.cbegin(), end = jidDevices.cend(); i != end; ++i) {
                // Since we use the (invalid) device ID 0 as sentinel, always
                // skip it just to be sure.
                if (i.key() == 0) continue;
                auto jidDevice = i.value();
                out << i.key()
                    << jidDevice.label
                    << jidDevice.keyId
                    << jidDevice.session
                    << (qint32) jidDevice.unrespondedSentStanzasCount
                    << (qint32) jidDevice.unrespondedReceivedStanzasCount
                    << jidDevice.removalFromDeviceListDate;
            }
            out << (uint32_t) 0;
        }
        w.close();
    }
}

static QHash<QString, QHash<uint32_t, QXmppOmemoStorage::Device>>
_deserializeDevices(QString name)
{
    QDir dir(_storagePath(name));
    QFile r(dir.filePath(QStringLiteral(u"devices")));
    QHash<QString, QHash<uint32_t, QXmppOmemoStorage::Device>> devices;

    if (r.open(QIODevice::ReadOnly)) {
        QDataStream in(&r);
        for (;;) {
            QHash<uint32_t, QXmppOmemoStorage::Device> jidDevices;
            QString jid;
            in >> jid;

            while (in.status() == QDataStream::Ok) {
                quint32 did;
                QXmppOmemoStorage::Device jidDevice;
                in >> did;
                if (did == 0) {
                    break;
                }
                qCDebug(qxmppOMEMO) << "DEVICE: " << jid << did;
                qint32 unrespondedSentStanzasCount;
                qint32 unrespondedReceivedStanzasCount;

                in >> jidDevice.label
                   >> jidDevice.keyId
                   >> jidDevice.session
                   >> unrespondedSentStanzasCount
                   >> unrespondedReceivedStanzasCount
                   >> jidDevice.removalFromDeviceListDate;
                jidDevice.unrespondedSentStanzasCount = unrespondedSentStanzasCount;
                jidDevice.unrespondedReceivedStanzasCount = unrespondedReceivedStanzasCount;
                jidDevices[did] = jidDevice;
            }

            if (in.status() != QDataStream::Ok) {
                break;
            }

            qCDebug(qxmppOMEMO) << "Deserializing: " << jid << jidDevices.count();
            devices[jid] = jidDevices;
        }
        r.close();
    }
    return devices;
}
