package teammates.ui.request;

import teammates.common.datatransfer.NotificationTargetUser;

/**
 * The request of marking all unread notification as read in account.
 */
public class MarkAllUnreadNotificationsAsReadRequest extends BasicRequest {
    private NotificationTargetUser targetUser;

    public NotificationTargetUser getTargetUser() {
        return this.targetUser;
    }

    @Override
    public void validate() throws InvalidHttpRequestBodyException {
        assertTrue(targetUser != NotificationTargetUser.GENERAL, "Target user should not be general.");
    }
}
