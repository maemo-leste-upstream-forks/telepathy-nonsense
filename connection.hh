/*
 * This file is part of the telepathy-nonsense connection manager.
 * Copyright (C) 2015 Niels Ole Salscheider <niels_ole@salscheider-online.de>
 * Copyright (C) 2014 Alexandr Akulich <akulichalexander@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#ifndef CONNECTION_HH
#define CONNECTION_HH

#include <TelepathyQt/BaseConnection>
#include <TelepathyQt/BaseChannel>

#include <QXmppClient.h>
#include <QXmppVCardIq.h>
#include <QXmppMessage.h>
#include <QXmppDiscoveryManager.h>
#include <QXmppTransferManager.h>
#if QXMPP_VERSION >= 0x000905
#include <QXmppCarbonManagerV2.h>
#endif
#include <Omemo/QXmppOmemoManager.h>
#include <Omemo/QXmppOmemoMemoryStorage.h>
#include <QXmppAtmManager.h>
#include <QXmppAtmTrustMemoryStorage.h>
#include <QXmppTrustManager.h>
#include <QXmppTrustMemoryStorage.h>

#include "textchannel.hh"
#include "uniquehandlemap.hh"
#include "omemostore.hh"

class QXmppMucManager;

class Connection : public Tp::BaseConnection
{
    Q_OBJECT
public:
    Connection(const QDBusConnection &dbusConnection,
            const QString &cmName, const QString &protocolName,
            const QVariantMap &parameters);

    QPointer<QXmppClient> qxmppClient() const;
    QString lastResourceForJid(const QString &jid, bool force = false);
    QString bestResourceForJid(const QString &jid) const;
    void setLastResource(const QString &jid, const QString &resource);

    uint ensureContactHandle(const QString &id);
    QString getContactIdentifier(uint handle) const;

    void updateJidPresence(const QString &jid, const QXmppPresence &presence);
    void updateMucParticipantInfo(const QString &participant, const QXmppPresence &presense);

private:
    void doConnect(Tp::DBusError *error);

    uint setPresence(const QString &status, const QString &message, Tp::DBusError *error);
    Tp::ContactAttributesMap getContactListAttributes(const QStringList &interfaces, bool hold, Tp::DBusError *error);
    Tp::ContactAttributesMap getContactAttributes(const Tp::UIntList &handles, const QStringList &interfaces, Tp::DBusError *error);
    QString getAlias(uint handle, Tp::DBusError *error);
    Tp::AliasMap getAliases(const Tp::UIntList &handles, Tp::DBusError *error);
    void setAliases(const Tp::AliasMap &aliases, Tp::DBusError *error);
    QStringList inspectHandles(uint handleType, const Tp::UIntList &handles, Tp::DBusError *error);
    Tp::UIntList requestHandles(uint handleType, const QStringList &identifiers, Tp::DBusError *error);
    void requestSubscription(const Tp::UIntList &handles, const QString &message, Tp::DBusError *error);
    void authorizePublication(const Tp::UIntList &handles, Tp::DBusError *error);
    void removeContacts(const Tp::UIntList &handles, Tp::DBusError *error);
    void unsubscribe(const Tp::UIntList &handles, Tp::DBusError *error);
    void unpublish(const Tp::UIntList &handles, Tp::DBusError *error);
    void saslStartMechanismWithData(const QString &mechanism, const QByteArray &data, Tp::DBusError *error);
    Tp::BaseChannelPtr createChannelCB(const QVariantMap &request, Tp::DBusError *error);
    void requestAvatars(const Tp::UIntList &handles, Tp::DBusError *error);
    Tp::AvatarTokenMap getKnownAvatarTokens(const Tp::UIntList &contacts, Tp::DBusError *error);
    void clearAvatar(Tp::DBusError *error);
    QString setAvatar(const QByteArray &avatar, const QString &mimetype, Tp::DBusError *error);

    TextChannelPtr getTextChannel(const QString &contactJid, bool ensure, bool mucInvitation);

    void updateGroups();
    void setContactGroups(uint contact, const QStringList &groups, Tp::DBusError *error);
    void setGroupMembers(const QString &group, const Tp::UIntList &members, Tp::DBusError *error);
    void addToGroup(const QString &group, const Tp::UIntList &members, Tp::DBusError *error);
    void removeFromGroup(const QString &group, const Tp::UIntList &members, Tp::DBusError *error);
    void removeGroup(const QString &group, Tp::DBusError *error);
    void renameGroup(const QString &oldName, const QString &newName, Tp::DBusError *error);

    QStringList getClientType(uint handle) const;
    Tp::ContactClientTypes getClientTypes(const Tp::UIntList &contacts, Tp::DBusError *error);
    QStringList requestClientTypes(uint contact, Tp::DBusError *error);

    Tp::ContactCapabilitiesMap getContactCapabilities(const Tp::UIntList &contacts, Tp::DBusError *error);

    Tp::SimplePresence toTpPresence(QMap<QString, QXmppPresence> presences);

private slots:
    void doDisconnect();

    void onConnected();
    void onError(QXmppClient::Error error);
    void onMessageReceived(const QXmppMessage &message);
    void onFileReceived(QXmppTransferJob *job);
    void onPresenceReceived(const QXmppPresence &presence);

    void onDiscoveryInfoReceived(const QXmppDiscoveryIq &iq);
    void onDiscoveryItemsReceived(const QXmppDiscoveryIq &iq);

    void onRosterReceived();
    void onPresenceChanged(const QString &bareJid, const QString &resource);
    void onSubscriptionRequestReceived(const QString &subscriberBareJid, const QXmppPresence &presence);

    void onVCardReceived(QXmppVCardIq);
    void onClientVCardReceived();

    void onLogMessage(QXmppLogger::MessageType type, const QString &text);

private:
    void updateAvatar(const QByteArray &photo, const QString &jid, const QString &type);

    Tp::BaseConnectionContactsInterfacePtr m_contactsIface;
    Tp::BaseConnectionSimplePresenceInterfacePtr m_simplePresenceIface;
    Tp::BaseConnectionContactListInterfacePtr m_contactListIface;
    Tp::BaseConnectionContactGroupsInterfacePtr m_contactGroupsIface;
    Tp::BaseConnectionAliasingInterfacePtr m_aliasingIface;
    Tp::BaseConnectionClientTypesInterfacePtr m_clientTypesIface;
    Tp::BaseConnectionContactCapabilitiesInterfacePtr m_contactCapabilitiesIface;
    Tp::BaseConnectionAvatarsInterfacePtr m_avatarsIface;
    Tp::BaseConnectionRequestsInterfacePtr m_requestsIface;
    Tp::BaseChannelSASLAuthenticationInterfacePtr m_saslIface;

    QPointer<QXmppClient> m_client;
    QXmppDiscoveryManager *m_discoveryManager;
    QXmppMucManager *m_mucManager;
    QXmppPresence m_clientPresence;
    QXmppConfiguration m_clientConfig;
    UniqueHandleMap m_uniqueContactHandleMap;
    UniqueHandleMap m_uniqueRoomHandleMap;
    QMap<QString, QString> m_avatarTokens;
    QMap<QString, QString> m_lastResources;
    QMap<QString, QStringList> m_contactsFeatures;
    QMap<QString, QString> m_clientTypes;
    QMap<QString, QXmppPresence> m_mucParticipants;
    QList<QString> m_serverEntities;

    std::unique_ptr<NonsenseOmemoStorage> m_omemoStorage;
    QXmppOmemoManager *m_omemoManager;
};

#endif // CONNECTION_HH
