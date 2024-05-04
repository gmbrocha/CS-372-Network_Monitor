# Modified from starter code created by/at
# Author: Bram Lewis
# Availability: https://canvas.oregonstate.edu/courses/1957923/assignments/9654612?module_item_id=24358446

import datetime


def timestamped_print(*args, **kwargs):
    """
    Custom print function that adds a timestamp to the beginning of the message.

    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments. These are passed to the built-in print function.
    """
    # Get the current time and format it
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print the timestamp followed by the original message
    print(f"[{timestamp}]: ", *args, **kwargs)

