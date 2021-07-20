import email.utils
import logging
import os
import time

from django.conf import settings
from django.contrib.sites.models import Site
from django.core import mail
from django.template.loader import render_to_string
from django.contrib.auth.models import Permission

from tickets.defaults import defaults
from tickets.models import Attachment, Comment, Task, MainMail, AdditionalMail


log = logging.getLogger(__name__)


def getMainMails():
    return MainMail.objects.values_list("email", flat=True)


def getAdditionalMails():
    return AdditionalMail.objects.values_list("email", flat=True)


def staff_check(user):
    """If TODO_STAFF_ONLY is set to True, limit view access to staff users only.
        # FIXME: More granular access control needed - see
        https://github.com/shacker/django-todo/issues/50
    """

    if defaults("TODO_STAFF_ONLY"):
        return user.is_staff
    else:
        # If unset or False, allow all logged in users
        return True


def user_can_read_task(task, user):
    p = Permission.objects.get(codename="class_b")
    class_b_group = p.group_set.first()

    return task.group in user.groups.all() or user.is_superuser or class_b_group in user.groups.all()


def todo_get_backend(task):
    """Returns a mail backend for some task"""
    mail_backends = getattr(settings, "TODO_MAIL_BACKENDS", None)
    if mail_backends is None:
        return None

    task_backend = mail_backends[task.task_list.slug]
    if task_backend is None:
        return None

    return task_backend


def todo_get_mailer(user, task):
    """A mailer is a (from_address, backend) pair"""
    task_backend = todo_get_backend(task)
    if task_backend is None:
        return (None, mail.get_connection)

    from_address = getattr(task_backend, "from_address")
    from_address = email.utils.formataddr((user.username, from_address))
    return (from_address, task_backend)


def todo_send_mail(user, task, subject, body, recip_list):
    """Send an email attached to task, triggered by user"""
    references = Comment.objects.filter(task=task).only("email_message_id")
    references = (ref.email_message_id for ref in references)
    references = " ".join(filter(bool, references))

    from_address, backend = todo_get_mailer(user, task)
    message_hash = hash((subject, body, from_address, frozenset(recip_list), references))

    message_id = (
        # the task_id enables attaching back notification answers
        "<notif-{task_id}."
        # the message hash / epoch pair enables deduplication
        "{message_hash:x}."
        "{epoch}@django-todo>"
    ).format(
        task_id=task.pk,
        # avoid the -hexstring case (hashes can be negative)
        message_hash=abs(message_hash),
        epoch=int(time.time()),
    )

    # the thread message id is used as a common denominator between all
    # notifications for some task. This message doesn't actually exist,
    # it's just there to make threading possible
    thread_message_id = "<thread-{}@django-todo>".format(task.pk)
    references = "{} {}".format(references, thread_message_id)
    with backend() as connection:
        message = mail.EmailMessage(
            subject,
            body,
            from_address,
            recip_list,
            [],  # Bcc
            headers={
                **getattr(backend, "headers", {}),
                "Message-ID": message_id,
                "References": references,
                "In-reply-to": thread_message_id,
            },
            connection=connection,
        )
        try:
            message.send()
        except Exception as err:
            log.error(f"Message sending error: {err}.")


def send_notify_mail(new_task):
    """
    Send email to assignee if task is assigned to someone other than submittor.
    Unassigned tasks should not try to notify.
    """

    current_site = Site.objects.get_current()
    subject = render_to_string("tickets/email/assigned_subject.txt", {"task": new_task})
    body = render_to_string(
        "tickets/email/assigned_body.txt", {"task": new_task, "site": current_site}
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_edit_notify_mail(new_task, subject, changes, user):
    """
    Send email when task is edited.
    """

    current_site = Site.objects.get_current()
    body = render_to_string(
        "tickets/email/edited_task_body.txt",
        {
            "task": new_task,
            "site": current_site,
            "changes": changes,
            "change_user": user,
        }
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_new_comment_notify_mail(new_task, subject, comment):
    """
    Send email when new comment is added for task.
    """

    current_site = Site.objects.get_current()
    body = render_to_string(
        "tickets/email/new_comment_body.txt",
        {
            "task": new_task,
            "site": current_site,
            "comment": comment,
        }
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_change_group_notify_mail(new_task, subject, group, change_user):
    """
    Send email when level of escalation is changed.
    """

    current_site = Site.objects.get_current()
    body = render_to_string(
        "tickets/email/change_group_body.txt",
        {
            "task": new_task,
            "site": current_site,
            "change_user": change_user,
            "class": group,
        }
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_solve_problem_notify_mail(new_task, subject, type, note, change_user):
    """
    Send email when problem is solved.
    """

    current_site = Site.objects.get_current()
    body = render_to_string(
        "tickets/email/change_group_body.txt",
        {
            "task": new_task,
            "site": current_site,
            "change_user": change_user,
            "type": type,
            "note": note,
        }
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_status_change_notify_mail(new_task, subject, user, finished):
    """
    Send email when task status is changed(completed/not completed).
    """

    current_site = Site.objects.get_current()
    body = render_to_string(
        "tickets/email/status_change_body.txt",
        {
            "task": new_task,
            "site": current_site,
            "change_user": user,
            "finished": finished,
        }
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in new_task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())
    todo_send_mail(new_task.created_by, new_task, subject, body, recip_list)


def send_email_to_thread_participants(task, msg_body, user, subject=None):
    """Notify all previous commentors on a Task about a new comment."""

    current_site = Site.objects.get_current()
    email_subject = subject
    if not subject:
        subject = render_to_string("tickets/email/assigned_subject.txt", {"task": task})

    email_body = render_to_string(
        "tickets/email/newcomment_body.txt",
        {"task": task, "body": msg_body, "site": current_site, "user": user},
    )

    recip_list = list(getMainMails())
    if 'special_class_email' in task.group.permissions.values_list('codename', flat=True):
        recip_list.extend(getAdditionalMails())

    todo_send_mail(user, task, email_subject, email_body, recip_list)


def toggle_task_completed(task_id: int, user) -> bool:
    """Toggle the `completed` bool on Task from True to False or vice versa."""
    try:
        task = Task.objects.get(id=task_id)
        task.completed = not task.completed
        task.save()
        if task.completed:
            comment_str = f"{user.username} маркира проблем с номер {task.id} като завършен"
            send_status_change_notify_mail(task, comment_str, user, True)

        else:
            comment_str = f"{user.username} маркира проблем с номер {task.id} като незавършен"
            send_status_change_notify_mail(task, comment_str, user, False)

        Comment.objects.create(author=task.created_by, task=task, body=comment_str)

        return True

    except Task.DoesNotExist:
        log.info(f"Task {task_id} not found.")
        return False


def remove_attachment_file(attachment_id: int) -> bool:
    """Delete an Attachment object and its corresponding file from the filesystem."""
    try:
        attachment = Attachment.objects.get(id=attachment_id)
        if attachment.file:
            if os.path.isfile(attachment.file.path):
                os.remove(attachment.file.path)

        attachment.delete()
        return True

    except Attachment.DoesNotExist:
        log.info(f"Attachment {attachment_id} not found.")
        return False


# Custom utils
def get_changes_string(user, form):
    initial_form = form.initial

    changes = ""
    if initial_form['title'] != form.cleaned_data['title']:
        changes += f" Заглавието е променено от '{initial_form['title']}' на '{form.cleaned_data['title']}'</br>"
    if initial_form['note'] != form.cleaned_data['note']:
        changes += f" Описанието е променено от '{initial_form['note']}' на '{form.cleaned_data['note']}'</br>"
    if initial_form['measures_taken'] != form.cleaned_data['measures_taken']:
        changes += f" Предприетите мерки са променени от '{initial_form['measures_taken']}' на '{form.cleaned_data['measures_taken']}'</br>"
    initial_errors = [x.name for x in initial_form['cause_of_error']]
    errors = [x.name for x in form.cleaned_data['cause_of_error']]
    if len(initial_errors) != len(errors):
        ie = ', '.join(initial_errors)
        err = ', '.join(errors)
        changes += f" Причините за проблема са променени от '{ie}' на '{err}'</br>"
    else:
        for error in initial_errors:
            if error not in errors:
                ie = ', '.join(initial_errors)
                err = ', '.join(errors)

                changes += f" Причините за проблема са променени от '{ie}' на '{err}'</br>"
                break
    if changes:
        start = f"Потребителят {user.get_full_name()} направи следните промени: </br>"

        changes = start + changes
    return changes
