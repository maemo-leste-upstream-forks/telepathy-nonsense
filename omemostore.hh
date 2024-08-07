#ifndef OMEMOSTORE_HH
#define OMEMOSTORE_HH

#include <QXmppOmemoStorage.h>
#include <QXmppTask.h>
//#include "qxmppomemo_export.h"

#include <memory>

class NonsenseOmemoStoragePrivate;

class NonsenseOmemoStorage : public QXmppOmemoStorage
{
public:
    NonsenseOmemoStorage(const QString);
    ~NonsenseOmemoStorage() override;

    /// \cond
    QXmppTask<OmemoData> allData() override;

    QXmppTask<void> setOwnDevice(const std::optional<OwnDevice> &device) override;

    QXmppTask<void> addSignedPreKeyPair(uint32_t keyId, const SignedPreKeyPair &keyPair) override;
    QXmppTask<void> removeSignedPreKeyPair(uint32_t keyId) override;

    QXmppTask<void> addPreKeyPairs(const QHash<uint32_t, QByteArray> &keyPairs) override;
    QXmppTask<void> removePreKeyPair(uint32_t keyId) override;

    QXmppTask<void> addDevice(const QString &jid, uint32_t deviceId, const Device &device) override;
    QXmppTask<void> removeDevice(const QString &jid, uint32_t deviceId) override;
    QXmppTask<void> removeDevices(const QString &jid) override;

    QXmppTask<void> resetAll() override;
    /// \endcond

private:
    std::unique_ptr<NonsenseOmemoStoragePrivate> d;
    QString name;
};

#endif // OMEMOSTORE_HH
