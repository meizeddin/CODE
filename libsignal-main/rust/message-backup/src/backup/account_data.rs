//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::num::NonZeroU32;

use derive_where::derive_where;
use usernames::constants::USERNAME_LINK_ENTROPY_SIZE;
use usernames::{Username, UsernameError};
use uuid::Uuid;
use zkgroup::ProfileKeyBytes;

use crate::backup::chat::chat_style::{ChatStyle, ChatStyleError};
use crate::backup::method::Method;
use crate::backup::time::Duration;
use crate::proto::backup as proto;

#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq;
    M::Value<ProfileKeyBytes>: PartialEq,
    M::Value<Option<UsernameData>>: PartialEq,
    M::Value<String>: PartialEq,
    M::Value<Option<Subscription>>: PartialEq,
    M::Value<AccountSettings>: PartialEq,
))]
pub struct AccountData<M: Method> {
    pub profile_key: M::Value<ProfileKeyBytes>,
    pub username: M::Value<Option<UsernameData>>,
    pub given_name: M::Value<String>,
    pub family_name: M::Value<String>,
    pub account_settings: M::Value<AccountSettings>,
    pub avatar_url_path: M::Value<String>,
    pub donation_subscription: M::Value<Option<Subscription>>,
    pub backup_subscription: M::Value<Option<Subscription>>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UsernameData {
    pub username: Username,
    pub link: Option<UsernameLink>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UsernameLink {
    pub color: crate::proto::backup::account_data::username_link::Color,
    pub entropy: [u8; USERNAME_LINK_ENTROPY_SIZE],
    pub server_id: Uuid,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Subscription {
    pub subscriber_id: SubscriberId,
    pub currency_code: String,
    pub manually_canceled: bool,
}

const SUBSCRIBER_ID_LENGTH: usize = 32;
type SubscriberId = [u8; SUBSCRIBER_ID_LENGTH];

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AccountSettings {
    pub phone_number_sharing: PhoneSharing,
    pub read_receipts: bool,
    pub sealed_sender_indicators: bool,
    pub typing_indicators: bool,
    pub link_previews: bool,
    pub not_discoverable_by_phone_number: bool,
    pub prefer_contact_avatars: bool,
    pub display_badges_on_profile: bool,
    pub keep_muted_chats_archived: bool,
    pub has_set_my_stories_privacy: bool,
    pub has_viewed_onboarding_story: bool,
    pub stories_disabled: bool,
    pub story_view_receipts_enabled: Option<bool>,
    pub has_seen_group_story_education_sheet: bool,
    pub has_completed_username_onboarding: bool,
    pub universal_expire_timer: Option<Duration>,
    pub preferred_reaction_emoji: Vec<String>,
    pub default_chat_style: Option<ChatStyle>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PhoneSharing {
    WithEverybody,
    WithNobody,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AccountDataError {
    /// profile key was invalid
    InvalidProfileKey,
    /// invalid username
    InvalidUsername(#[from] UsernameError),
    /// no account settings found
    MissingSettings,
    /// account settings phone number sharing mode is UNKNOWN
    UnknownPhoneNumberSharingMode,
    /// username link is present without username
    UsernameLinkWithoutUsername,
    /// username entropy should have been {USERNAME_LINK_ENTROPY_SIZE:?} bytes but was {0}
    BadUsernameEntropyLength(usize),
    /// username server ID should be a UUID but was {0} bytes
    BadUsernameServerIdLength(usize),
    /// subscriber currency code was present but not the ID
    SubscriberCurrencyWithoutId,
    /// chat style: {0}
    ChatStyle(#[from] ChatStyleError),
    /// donation subscription: {0}
    DonationSubscription(SubscriptionError),
    /// backups subscription: {0}
    BackupSubscription(SubscriptionError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SubscriptionError {
    /// subscriber ID should have {SUBSCRIBER_ID_LENGTH:?} bytes but had {0}
    InvalidSubscriberId(usize),
    /// subscriber ID was present but not the currency code
    EmptyCurrency,
}

impl<M: Method> TryFrom<proto::AccountData> for AccountData<M> {
    type Error = AccountDataError;
    fn try_from(proto: proto::AccountData) -> Result<Self, Self::Error> {
        let proto::AccountData {
            profileKey,
            username,
            givenName,
            familyName,
            accountSettings,
            usernameLink,
            avatarUrlPath,
            donationSubscriberData,
            backupsSubscriberData,
            special_fields: _,
        } = proto;

        let profile_key = ProfileKeyBytes::try_from(profileKey)
            .map_err(|_| AccountDataError::InvalidProfileKey)?;

        let username = match username {
            None => {
                if usernameLink.is_some() {
                    return Err(AccountDataError::UsernameLinkWithoutUsername);
                }
                None
            }
            Some(username) => Some((username, usernameLink.into_option()).try_into()?),
        };

        let account_settings = accountSettings
            .into_option()
            .ok_or(AccountDataError::MissingSettings)?
            .try_into()?;

        let donation_subscription = donationSubscriberData
            .into_option()
            .map(Subscription::try_from)
            .transpose()
            .map_err(AccountDataError::DonationSubscription)?;
        let backup_subscription = backupsSubscriberData
            .into_option()
            .map(Subscription::try_from)
            .transpose()
            .map_err(AccountDataError::BackupSubscription)?;

        Ok(Self {
            profile_key: M::value(profile_key),
            username: M::value(username),
            given_name: M::value(givenName),
            family_name: M::value(familyName),
            account_settings: M::value(account_settings),
            avatar_url_path: M::value(avatarUrlPath),
            donation_subscription: M::value(donation_subscription),
            backup_subscription: M::value(backup_subscription),
        })
    }
}

impl TryFrom<proto::account_data::SubscriberData> for Subscription {
    type Error = SubscriptionError;

    fn try_from(value: proto::account_data::SubscriberData) -> Result<Self, Self::Error> {
        let proto::account_data::SubscriberData {
            subscriberId,
            currencyCode,
            manuallyCancelled,
            special_fields: _,
        } = value;
        let subscriber_id = subscriberId
            .try_into()
            .map_err(|id: Vec<u8>| SubscriptionError::InvalidSubscriberId(id.len()))?;

        if currencyCode.is_empty() {
            return Err(SubscriptionError::EmptyCurrency);
        }
        let currency_code = currencyCode;

        Ok(Subscription {
            subscriber_id,
            currency_code,
            manually_canceled: manuallyCancelled,
        })
    }
}

impl TryFrom<(String, Option<proto::account_data::UsernameLink>)> for UsernameData {
    type Error = AccountDataError;

    fn try_from(
        (username, username_link): (String, Option<proto::account_data::UsernameLink>),
    ) -> Result<Self, Self::Error> {
        let username = Username::new(&username)?;
        let link = username_link.map(TryInto::try_into).transpose()?;
        Ok(UsernameData { username, link })
    }
}

impl TryFrom<proto::account_data::UsernameLink> for UsernameLink {
    type Error = AccountDataError;

    fn try_from(value: proto::account_data::UsernameLink) -> Result<Self, Self::Error> {
        let proto::account_data::UsernameLink {
            color,
            entropy,
            serverId,
            special_fields: _,
        } = value;
        // The color is allowed to be unset.
        let color = color.enum_value_or_default();
        let entropy = entropy.try_into().map_err(|entropy: Vec<u8>| {
            AccountDataError::BadUsernameEntropyLength(entropy.len())
        })?;
        let server_id = serverId
            .try_into()
            .map_err(|id: Vec<u8>| AccountDataError::BadUsernameServerIdLength(id.len()))?;
        let server_id = Uuid::from_bytes(server_id);
        Ok(Self {
            color,
            entropy,
            server_id,
        })
    }
}

impl TryFrom<proto::account_data::AccountSettings> for AccountSettings {
    type Error = AccountDataError;

    fn try_from(value: proto::account_data::AccountSettings) -> Result<Self, Self::Error> {
        let proto::account_data::AccountSettings {
            phoneNumberSharingMode,
            readReceipts,
            sealedSenderIndicators,
            typingIndicators,
            linkPreviews,
            notDiscoverableByPhoneNumber,
            preferContactAvatars,
            displayBadgesOnProfile,
            keepMutedChatsArchived,
            hasSetMyStoriesPrivacy,
            hasViewedOnboardingStory,
            storiesDisabled,
            storyViewReceiptsEnabled,
            hasSeenGroupStoryEducationSheet,
            hasCompletedUsernameOnboarding,
            universalExpireTimer,
            preferredReactionEmoji,
            defaultChatStyle,
            special_fields: _,
        } = value;

        use proto::account_data::PhoneNumberSharingMode;
        let phone_number_sharing = match phoneNumberSharingMode.enum_value_or_default() {
            PhoneNumberSharingMode::UNKNOWN => {
                return Err(AccountDataError::UnknownPhoneNumberSharingMode)
            }
            PhoneNumberSharingMode::EVERYBODY => PhoneSharing::WithEverybody,
            PhoneNumberSharingMode::NOBODY => PhoneSharing::WithNobody,
        };

        let default_chat_style = defaultChatStyle
            .into_option()
            .map(ChatStyle::try_from)
            .transpose()?;

        let universal_expire_timer =
            NonZeroU32::new(universalExpireTimer).map(|d| Duration::from_millis(d.get().into()));

        Ok(Self {
            phone_number_sharing,
            default_chat_style,
            read_receipts: readReceipts,
            sealed_sender_indicators: sealedSenderIndicators,
            typing_indicators: typingIndicators,
            link_previews: linkPreviews,
            not_discoverable_by_phone_number: notDiscoverableByPhoneNumber,
            prefer_contact_avatars: preferContactAvatars,
            display_badges_on_profile: displayBadgesOnProfile,
            keep_muted_chats_archived: keepMutedChatsArchived,
            has_set_my_stories_privacy: hasSetMyStoriesPrivacy,
            has_viewed_onboarding_story: hasViewedOnboardingStory,
            stories_disabled: storiesDisabled,
            story_view_receipts_enabled: storyViewReceiptsEnabled,
            has_seen_group_story_education_sheet: hasSeenGroupStoryEducationSheet,
            has_completed_username_onboarding: hasCompletedUsernameOnboarding,
            preferred_reaction_emoji: preferredReactionEmoji,
            universal_expire_timer,
        })
    }
}

#[cfg(test)]
mod test {
    use protobuf::EnumOrUnknown;
    use test_case::test_case;
    use uuid::Uuid;

    use crate::backup::method::{Store, ValidateOnly};

    use super::*;

    impl proto::AccountData {
        pub(crate) fn test_data() -> Self {
            Self {
                profileKey: FAKE_PROFILE_KEY.into(),
                accountSettings: Some(proto::account_data::AccountSettings::test_data()).into(),
                username: Some("abc.123".to_string()),
                usernameLink: Some(proto::account_data::UsernameLink {
                    color: proto::account_data::username_link::Color::BLUE.into(),
                    entropy: FAKE_USERNAME_LINK_ENTROPY.to_vec(),
                    serverId: FAKE_USERNAME_SERVER_ID.into_bytes().to_vec(),
                    ..Default::default()
                })
                .into(),
                backupsSubscriberData: Some(proto::account_data::SubscriberData {
                    subscriberId: FAKE_SUBSCRIBER_ID.to_vec(),
                    currencyCode: "XTS".to_string(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }
    }

    impl proto::account_data::AccountSettings {
        fn test_data() -> Self {
            Self {
                phoneNumberSharingMode: proto::account_data::PhoneNumberSharingMode::EVERYBODY
                    .into(),
                ..Default::default()
            }
        }
    }

    const FAKE_PROFILE_KEY: ProfileKeyBytes = [0xaa; 32];
    const FAKE_SUBSCRIBER_ID: SubscriberId = [55; 32];
    const FAKE_USERNAME_LINK_ENTROPY: [u8; USERNAME_LINK_ENTROPY_SIZE] = [12; 32];
    const FAKE_USERNAME_SERVER_ID: Uuid = Uuid::from_bytes([10; 16]);

    #[test]
    fn valid_account_data() {
        assert_eq!(
            proto::AccountData::test_data().try_into(),
            Ok(AccountData::<Store> {
                profile_key: FAKE_PROFILE_KEY,
                username: Some(UsernameData {
                    username: Username::new("abc.123").unwrap(),
                    link: Some(UsernameLink {
                        color: proto::account_data::username_link::Color::BLUE,
                        entropy: FAKE_USERNAME_LINK_ENTROPY,
                        server_id: FAKE_USERNAME_SERVER_ID
                    })
                }),
                given_name: "".to_string(),
                family_name: "".to_string(),
                account_settings: AccountSettings {
                    phone_number_sharing: PhoneSharing::WithEverybody,
                    default_chat_style: None,
                    read_receipts: false,
                    sealed_sender_indicators: false,
                    typing_indicators: false,
                    link_previews: false,
                    not_discoverable_by_phone_number: false,
                    prefer_contact_avatars: false,
                    display_badges_on_profile: false,
                    keep_muted_chats_archived: false,
                    has_set_my_stories_privacy: false,
                    has_viewed_onboarding_story: false,
                    stories_disabled: false,
                    story_view_receipts_enabled: None,
                    has_seen_group_story_education_sheet: false,
                    has_completed_username_onboarding: false,
                    universal_expire_timer: None,
                    preferred_reaction_emoji: vec![],
                },
                avatar_url_path: "".to_string(),
                backup_subscription: Some(Subscription {
                    subscriber_id: FAKE_SUBSCRIBER_ID,
                    currency_code: "XTS".to_string(),
                    manually_canceled: false,
                }),
                donation_subscription: None,
            })
        )
    }

    fn invalid_profile_key(target: &mut proto::AccountData) {
        target.profileKey.clear();
    }
    fn invalid_username(target: &mut proto::AccountData) {
        target.username = Some("invalid".to_string());
    }
    fn no_username(target: &mut proto::AccountData) {
        target.username = None;
        target.usernameLink = None.into();
    }
    fn no_username_link(target: &mut proto::AccountData) {
        target.usernameLink = None.into();
    }
    fn username_link_unknown_color(target: &mut proto::AccountData) {
        target.usernameLink.as_mut().unwrap().color = EnumOrUnknown::default();
    }
    fn username_link_without_username(target: &mut proto::AccountData) {
        target.username = None;
        target.usernameLink = Some(target.usernameLink.take().unwrap()).into();
    }
    fn no_account_settings(target: &mut proto::AccountData) {
        target.accountSettings = None.into();
    }
    fn invalid_subscriber_id(target: &mut proto::AccountData) {
        target.backupsSubscriberData.as_mut().unwrap().subscriberId = vec![123];
    }
    fn empty_subscriber_id(target: &mut proto::AccountData) {
        target.backupsSubscriberData.as_mut().unwrap().subscriberId = vec![];
    }
    fn empty_subscriber_currency(target: &mut proto::AccountData) {
        target.backupsSubscriberData.as_mut().unwrap().currencyCode = "".to_owned();
    }
    fn no_subscriptions(target: &mut proto::AccountData) {
        target.backupsSubscriberData = None.into();
        target.donationSubscriberData = None.into();
    }

    #[test_case(invalid_profile_key, Err(AccountDataError::InvalidProfileKey))]
    #[test_case(
        invalid_username,
        Err(AccountDataError::InvalidUsername(UsernameError::MissingSeparator))
    )]
    #[test_case(no_username, Ok(()))]
    #[test_case(no_username_link, Ok(()))]
    #[test_case(username_link_unknown_color, Ok(()))]
    #[test_case(
        username_link_without_username,
        Err(AccountDataError::UsernameLinkWithoutUsername)
    )]
    #[test_case(no_account_settings, Err(AccountDataError::MissingSettings))]
    #[test_case(
        invalid_subscriber_id,
        Err(AccountDataError::BackupSubscription(SubscriptionError::InvalidSubscriberId(1)))
    )]
    #[test_case(
        empty_subscriber_id,
        Err(AccountDataError::BackupSubscription(SubscriptionError::InvalidSubscriberId(0)))
    )]
    #[test_case(
        empty_subscriber_currency,
        Err(AccountDataError::BackupSubscription(SubscriptionError::EmptyCurrency))
    )]
    #[test_case(no_subscriptions, Ok(()))]
    fn with(
        modifier: impl FnOnce(&mut proto::AccountData),
        expected: Result<(), AccountDataError>,
    ) {
        let mut data = proto::AccountData::test_data();
        modifier(&mut data);

        assert_eq!(
            AccountData::<ValidateOnly>::try_from(data).map(|_| ()),
            expected
        )
    }
}
