#include <QDir>
#include <QUrl>
#include <QDataStream>
#include <QXmppPromise.h>

#include "omemostore.hh"
#include "common.hh"

static QString _storagePath(QString name)
{
    QDir dir(QDir::homePath());
    QDir omemoDir(dir.filePath(QStringLiteral(u".config/telepathy-nonsense/omemo/")));
    omemoDir.mkdir(name);
    return omemoDir.filePath(name);
}


#include "omemostore_util.hh"


// Per-JID devices
class NonsenseOmemoStoragePrivate
{
public:
    bool isSetUp = false;

    std::optional<QXmppOmemoStorage::OwnDevice> ownDevice;

    // IDs of pre key pairs mapped to prekey pairs
    QHash<uint32_t, QByteArray> preKeyPairs;

    // IDs of signed pre key pairs mapped to signed prekey pairs
    QHash<uint32_t, QXmppOmemoStorage::SignedPreKeyPair> signedPreKeyPairs;

    // Recipient JID mapped to device ID mapped to device
    QHash<QString, QHash<uint32_t, QXmppOmemoStorage::Device>> devices;
};

NonsenseOmemoStorage::NonsenseOmemoStorage(const QString name)
    : d(new NonsenseOmemoStoragePrivate)
{
    this->name = QString::fromUtf8(QUrl::toPercentEncoding(name));
}

NonsenseOmemoStorage::~NonsenseOmemoStorage() = default;

/// \cond
QXmppTask<QXmppOmemoStorage::OmemoData> NonsenseOmemoStorage::allData()
{
    // ...
    auto od = _deserializeOwnDevice(this->name);
    if (!od.has_value()) {
        qCDebug(qxmppOMEMO) << "OMEMO state load failed!";
        return makeReadyTask(OmemoData{});
    }

    auto spkps = _deserializeSignedPreKeyPairs(this->name);
    auto pkps = _deserializePreKeyPairs(this->name);
    auto devices = _deserializeDevices(this->name);

    qCDebug(qxmppOMEMO) << "OMEMO state loaded. SPKP: " << spkps.count() <<
            " PKP: " << pkps.count() <<
            " JID+Devices: " << devices.count();
    qCDebug(qxmppOMEMO) << "OMEMO own device:" << od->id << od->label
        << od->publicIdentityKey.toHex();

    return makeReadyTask(OmemoData{od, spkps, pkps, devices});
}

QXmppTask<void> NonsenseOmemoStorage::setOwnDevice(const std::optional<OwnDevice> &device)
{
    d->ownDevice = device;
    if (!device.has_value()) {
        // TODO: remove ownDevice?
        qCDebug(qxmppOMEMO) << "-!- OMEMO setOwnDevice NULL";
        return makeReadyTask();
    }
    auto d = device.value();
    qCDebug(qxmppOMEMO) << "-!- OMEMO setOwnDevice" << d.id << d.label;
    _serializeOwnDevice(this->name, d);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::addSignedPreKeyPair(const uint32_t keyId, const SignedPreKeyPair &keyPair)
{
    d->signedPreKeyPairs.insert(keyId, keyPair);
    _serializeSignedPreKeyPairs(this->name, d->signedPreKeyPairs);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::removeSignedPreKeyPair(const uint32_t keyId)
{
    d->signedPreKeyPairs.remove(keyId);
    _serializeSignedPreKeyPairs(this->name, d->signedPreKeyPairs);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::addPreKeyPairs(const QHash<uint32_t, QByteArray> &keyPairs)
{
    d->preKeyPairs.insert(keyPairs);
    _serializePreKeyPairs(this->name, d->preKeyPairs);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::removePreKeyPair(const uint32_t keyId)
{
    d->preKeyPairs.remove(keyId);
    _serializePreKeyPairs(this->name, d->preKeyPairs);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::addDevice(const QString &jid, const uint32_t deviceId, const QXmppOmemoStorage::Device &device)
{
    d->devices[jid].insert(deviceId, device);
    _serializeDevices(this->name, d->devices);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::removeDevice(const QString &jid, const uint32_t deviceId)
{
    auto &devices = d->devices[jid];
    devices.remove(deviceId);

    // Remove the container for the passed JID if the container stores no
    // devices anymore.
    if (devices.isEmpty()) {
        d->devices.remove(jid);
    }

    _serializeDevices(this->name, d->devices);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::removeDevices(const QString &jid)
{
    d->devices.remove(jid);
    _serializeDevices(this->name, d->devices);
    return makeReadyTask();
}

QXmppTask<void> NonsenseOmemoStorage::resetAll()
{
    d.reset(new NonsenseOmemoStoragePrivate());
    return makeReadyTask();
}
/// \endcond
