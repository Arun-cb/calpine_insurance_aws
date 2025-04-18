# signals.py
from django.db.models.signals import pre_save, post_save, pre_delete
from django.dispatch import receiver
from django.db import transaction, connection
from .models import SystemAuditLog
import threading
from .middleware import audit_context

EXC_AUDITED_TABLES = ['tb_sc_session', 'tb_sc_system_audit_log']
SOFT_DELETE_FIELD = 'delete_flag' 

def table_exists(table_name):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = %s", [table_name]
        )
        return cursor.fetchone()[0] > 0

# Thread-local storage for audit context
# audit_context = threading.local()

# Dictionary to store pre-save states
pre_save_states = {}

def log_audit_entry(table_name, record_id, action, user_id, prev_data, curr_data):
    SystemAuditLog.objects.create(
        windowname=getattr(audit_context, 'windowname', 'Background Task'),
        table_name=table_name,
        record_id=record_id,
        action=action,
        last_updated_by=user_id,  # Direct from model
        previous_value=prev_data,
        current_value=curr_data
    )

@receiver(pre_save)
def capture_pre_save_state(sender, instance, **kwargs):

    # Skip signal logic during migrations
    if 'migrate' in connection.settings_dict.get('NAME', ''):
        return
    
        # Check if the table exists
    if not table_exists('tb_sc_system_audit_log'):
        return  # Skip signal logic if the table doesn't exist
    
    """Capture state before save"""
    table_name = sender._meta.db_table
    if table_name in EXC_AUDITED_TABLES:
        return

    if instance.pk:  # Existing instance being updated
        try:
            original = sender.objects.get(pk=instance.pk)
            pre_save_states[instance.pk] = {
                field.name: getattr(original, field.name)
                for field in sender._meta.fields
            }
        except sender.DoesNotExist:
            pre_save_states[instance.pk] = None

@receiver(post_save)
def handle_save(sender, instance, created, **kwargs):

    # Skip signal logic during migrations
    if 'migrate' in connection.settings_dict.get('NAME', ''):
        return
    
    # Check if the table exists
    if not table_exists('tb_sc_system_audit_log'):
        return  # Skip signal logic if the table doesn't exist
    

    """Handle create/update/soft-delete"""
    table_name = sender._meta.db_table
    if table_name in EXC_AUDITED_TABLES:
        return

    action = 'CREATE' if created else 'UPDATE'
    # instance.last_updated_by
    user_id = getattr(instance, 'last_updated_by', None)
    prev_data = {}
    curr_data = {}

    # Handle updates and soft deletes
    if not created:
        original_data = pre_save_states.get(instance.pk, {})
        
        # Detect soft delete
        if hasattr(instance, SOFT_DELETE_FIELD):
            is_deleted = getattr(instance, SOFT_DELETE_FIELD)
            was_deleted = original_data.get(SOFT_DELETE_FIELD, False)
            
            if not was_deleted and is_deleted:
                action = 'DELETE'

        # Build change data
        for field in sender._meta.fields:
            field_name = field.name
            old_val = original_data.get(field_name)
            new_val = getattr(instance, field_name)
            
            if action == 'DELETE':
                prev_data[field_name] = str(old_val)
            elif old_val != new_val:
                prev_data[field_name] = str(old_val)
                curr_data[field_name] = str(new_val)

    # Handle creates
    else:
        curr_data = {
            field.name: str(getattr(instance, field.name))
            for field in sender._meta.fields
        }

    # Create audit entry if changes detected
    if prev_data or curr_data:
        transaction.on_commit(
        lambda: log_audit_entry(
            sender._meta.db_table,
            instance.pk,
            action,
            user_id,
            prev_data,
            curr_data
        )
    )
    
    # Cleanup pre-save state
    if instance.pk in pre_save_states:
        del pre_save_states[instance.pk]

@receiver(pre_delete)
def handle_hard_delete(sender, instance, **kwargs):

    # Skip signal logic during migrations
    if 'migrate' in connection.settings_dict.get('NAME', ''):
        return
    
    # Check if the table exists
    if not table_exists('tb_sc_system_audit_log'):
        return  # Skip signal logic if the table doesn't exist
    
    
    """Handle hard deletes (if needed)"""
    table_name = sender._meta.db_table
    if table_name in EXC_AUDITED_TABLES:
        return

    prev_data = {
        field.name: str(getattr(instance, field.name))
        for field in sender._meta.fields
    }
    
    transaction.on_commit

