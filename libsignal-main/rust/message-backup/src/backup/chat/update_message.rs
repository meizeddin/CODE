// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::call::{GroupCall, IndividualCall};
use crate::backup::chat::group::GroupChatUpdate;
use crate::backup::chat::ChatItemError;
use crate::backup::frame::RecipientId;
use crate::backup::method::Contains;
use crate::backup::time::Duration;
use crate::backup::{TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

/// Validated version of [`proto::chat_update_message::Update`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum UpdateMessage {
    Simple(SimpleChatUpdate),
    GroupChange { updates: Vec<GroupChatUpdate> },
    ExpirationTimerChange { expires_in: Duration },
    ProfileChange { previous: String, new: String },
    ThreadMerge,
    SessionSwitchover,
    IndividualCall(IndividualCall),
    GroupCall(GroupCall),
    LearnedProfileUpdate(proto::learned_profile_chat_update::PreviousName),
}

/// Validated version of [`proto::simple_chat_update::Type`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SimpleChatUpdate {
    JoinedSignal,
    IdentityUpdate,
    IdentityVerified,
    IdentityDefault,
    ChangeNumber,
    BoostRequest,
    EndSession,
    ChatSessionRefresh,
    BadDecrypt,
    PaymentsActivated,
    PaymentActivationRequest,
    UnsupportedProtocolMessage,
}

impl<R: Contains<RecipientId>> TryFromWith<proto::ChatUpdateMessage, R> for UpdateMessage {
    type Error = ChatItemError;

    fn try_from_with(item: proto::ChatUpdateMessage, context: &R) -> Result<Self, Self::Error> {
        let proto::ChatUpdateMessage {
            update,
            special_fields: _,
        } = item;

        let update = update.ok_or(ChatItemError::UpdateIsEmpty)?;

        use proto::chat_update_message::Update;
        Ok(match update {
            Update::SimpleUpdate(proto::SimpleChatUpdate {
                type_,
                special_fields: _,
            }) => UpdateMessage::Simple({
                use proto::simple_chat_update::Type;
                match type_.enum_value_or_default() {
                    Type::UNKNOWN => return Err(ChatItemError::ChatUpdateUnknown),
                    Type::JOINED_SIGNAL => SimpleChatUpdate::JoinedSignal,
                    Type::IDENTITY_UPDATE => SimpleChatUpdate::IdentityUpdate,
                    Type::IDENTITY_VERIFIED => SimpleChatUpdate::IdentityVerified,
                    Type::IDENTITY_DEFAULT => SimpleChatUpdate::IdentityDefault,
                    Type::CHANGE_NUMBER => SimpleChatUpdate::ChangeNumber,
                    Type::BOOST_REQUEST => SimpleChatUpdate::BoostRequest,
                    Type::END_SESSION => SimpleChatUpdate::EndSession,
                    Type::CHAT_SESSION_REFRESH => SimpleChatUpdate::ChatSessionRefresh,
                    Type::BAD_DECRYPT => SimpleChatUpdate::BadDecrypt,
                    Type::PAYMENTS_ACTIVATED => SimpleChatUpdate::PaymentsActivated,
                    Type::PAYMENT_ACTIVATION_REQUEST => SimpleChatUpdate::PaymentActivationRequest,
                    Type::UNSUPPORTED_PROTOCOL_MESSAGE => {
                        SimpleChatUpdate::UnsupportedProtocolMessage
                    }
                }
            }),
            Update::GroupChange(proto::GroupChangeChatUpdate {
                updates,
                special_fields: _,
            }) => {
                if updates.is_empty() {
                    return Err(ChatItemError::GroupChangeIsEmpty);
                }
                UpdateMessage::GroupChange {
                    updates: updates
                        .into_iter()
                        .enumerate()
                        .map(
                            |(
                                i,
                                proto::group_change_chat_update::Update {
                                    update,
                                    special_fields: _,
                                },
                            )| {
                                let update =
                                    update.ok_or(ChatItemError::GroupChangeUpdateIsEmpty(i))?;
                                GroupChatUpdate::try_from(update).map_err(ChatItemError::from)
                            },
                        )
                        .collect::<Result<_, _>>()?,
                }
            }
            Update::ExpirationTimerChange(proto::ExpirationTimerChatUpdate {
                expiresInMs,
                special_fields: _,
            }) => UpdateMessage::ExpirationTimerChange {
                expires_in: Duration::from_millis(expiresInMs.into()),
            },
            Update::ProfileChange(proto::ProfileChangeChatUpdate {
                previousName,
                newName,
                special_fields: _,
            }) => UpdateMessage::ProfileChange {
                previous: previousName,
                new: newName,
            },
            Update::ThreadMerge(proto::ThreadMergeChatUpdate {
                special_fields: _,
                // TODO validate this field
                previousE164: _,
            }) => UpdateMessage::ThreadMerge,
            Update::SessionSwitchover(proto::SessionSwitchoverChatUpdate {
                special_fields: _,
                // TODO validate this field
                e164: _,
            }) => UpdateMessage::SessionSwitchover,
            Update::IndividualCall(call) => UpdateMessage::IndividualCall(call.try_into()?),
            Update::GroupCall(call) => UpdateMessage::GroupCall(call.try_into_with(context)?),
            Update::LearnedProfileChange(proto::LearnedProfileChatUpdate {
                previousName,
                special_fields: _,
            }) => UpdateMessage::LearnedProfileUpdate(
                previousName.ok_or(ChatItemError::LearnedProfileIsEmpty)?,
            ),
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use crate::backup::call::CallError;
    use crate::backup::chat::testutil::TestContext;
    use crate::proto::backup::chat_update_message::Update as ChatUpdateProto;

    use super::*;

    impl proto::SimpleChatUpdate {
        pub(crate) fn test_data() -> Self {
            Self {
                type_: proto::simple_chat_update::Type::IDENTITY_VERIFIED.into(),
                ..Default::default()
            }
        }
    }

    const BAD_RECIPIENT: RecipientId = RecipientId(u64::MAX);

    impl proto::GroupCall {
        fn no_started_call() -> Self {
            Self {
                startedCallRecipientId: None,
                ..Self::test_data()
            }
        }

        fn bad_started_call() -> Self {
            Self {
                startedCallRecipientId: Some(BAD_RECIPIENT.0),
                ..Self::test_data()
            }
        }
    }

    #[test_case(ChatUpdateProto::IndividualCall(proto::IndividualCall::test_data()), Ok(()))]
    #[test_case(ChatUpdateProto::GroupCall(proto::GroupCall::test_data()), Ok(()))]
    #[test_case(
        ChatUpdateProto::GroupCall(proto::GroupCall::no_started_call()),
        Ok(())
    )]
    #[test_case(
        ChatUpdateProto::GroupCall(proto::GroupCall::bad_started_call()),
        Err(CallError::UnknownCallStarter(BAD_RECIPIENT))
    )]
    fn call_chat_update(update: ChatUpdateProto, expected: Result<(), CallError>) {
        assert_eq!(
            proto::ChatUpdateMessage {
                update: Some(update),
                special_fields: Default::default()
            }
            .try_into_with(&TestContext::default())
            .map(|_: UpdateMessage| ()),
            expected.map_err(ChatItemError::Call)
        );
    }

    #[test]
    fn chat_update_message_no_item() {
        assert_matches!(
            UpdateMessage::try_from_with(
                proto::ChatUpdateMessage::default(),
                &TestContext::default()
            ),
            Err(ChatItemError::UpdateIsEmpty)
        );
    }

    #[test_case(proto::SimpleChatUpdate::test_data(), Ok(()))]
    #[test_case(proto::ExpirationTimerChatUpdate::default(), Ok(()))]
    #[test_case(proto::ProfileChangeChatUpdate::default(), Ok(()))]
    #[test_case(proto::ThreadMergeChatUpdate::default(), Ok(()))]
    #[test_case(proto::SessionSwitchoverChatUpdate::default(), Ok(()))]
    #[test_case(
        proto::LearnedProfileChatUpdate::default(),
        Err(ChatItemError::LearnedProfileIsEmpty)
    )]
    fn chat_update_message_item(
        update: impl Into<proto::chat_update_message::Update>,
        expected: Result<(), ChatItemError>,
    ) {
        let result = proto::ChatUpdateMessage {
            update: Some(update.into()),
            ..Default::default()
        }
        .try_into_with(&TestContext::default())
        .map(|_: UpdateMessage| ());

        assert_eq!(result, expected)
    }
}
