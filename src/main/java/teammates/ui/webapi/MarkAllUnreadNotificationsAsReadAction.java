package teammates.ui.webapi;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import teammates.common.exception.EntityDoesNotExistException;
import teammates.common.exception.InvalidParametersException;
import teammates.ui.output.ReadNotificationsData;
import teammates.ui.request.InvalidHttpRequestBodyException;
import teammates.ui.request.MarkAllUnreadNotificationsAsReadRequest;
import teammates.common.datatransfer.NotificationTargetUser;

public class MarkAllUnreadNotificationsAsReadAction extends Action {
    @Override
    AuthType getMinAuthLevel() {
        return AuthType.LOGGED_IN;
    }

    @Override
    void checkSpecificAccessControl() throws UnauthorizedAccessException {
        // Any user can create a read status for all notifications.
    }

    @Override
    public ActionResult execute() throws InvalidHttpRequestBodyException, InvalidOperationException {
        getAndValidateRequestBody(MarkAllUnreadNotificationsAsReadRequest.class);
        NotificationTargetUser targetUser =
                userInfo.isInstructor
                ? NotificationTargetUser.INSTRUCTOR
                : NotificationTargetUser.STUDENT;

        try {
            List<UUID> readNotifications =
                    sqlLogic.updateAllReadNotifications(userInfo.getId(), targetUser);
            ReadNotificationsData output = new ReadNotificationsData(
                    readNotifications.stream().map(UUID::toString).collect(Collectors.toList()));
            return new JsonResult(output);
        } catch (EntityDoesNotExistException e) {
            throw new EntityNotFoundException(e);
        } catch (InvalidParametersException e) {
            throw new InvalidHttpRequestBodyException(e);
        }
    }
}
