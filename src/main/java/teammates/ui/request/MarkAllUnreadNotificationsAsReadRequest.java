package teammates.ui.request;

/**
 * The request of marking all unread notification as read in account.
 */
public class MarkAllUnreadNotificationsAsReadRequest extends BasicRequest {
    @Override
    public void validate() throws InvalidHttpRequestBodyException {
        // Nothing to validate
    }
}
