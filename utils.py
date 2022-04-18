from collections import defaultdict
import json
import re

from canvasapi import Canvas

from flask import current_app


def get_tool_info(whitelist, tool_name):
    """
    Search the whitelist by tool name.

    :returns: A dictionary , or none if no tool matching that name was found.
    :rtype: dict or None
    """
    for category, category_tools in whitelist.items():
        for tool_info in category_tools:
            if tool_info.get("name") == tool_name:
                tool_info.update({"category": category})
                return tool_info

    return None


def filter_tool_list(course_id, access_token):
    """
    Filter tool list down to those on whitelist and sort by category.

    :param course_id: The Canvas ID of the course to get the tools for.
    :type course_id: int
    :param access_token: The access token (API key) to use.
    :type access_token: str

    :rtype: dict
    :returns: A dictionary where the keys are tool categories.
        The values are a list of all installed external tools that are
        in that category and on the whitelist.
    """
    with open(current_app.config['WHITELIST'], "r") as wl_file:
        whitelist = json.loads(wl_file.read())

    if not whitelist:
        raise ValueError("whitelist.json is empty")

    canvas = Canvas(current_app.config['BASE_URL'], access_token)

    course = canvas.get_course(course_id)
    installed_tools = course.get_external_tools(include_parents=True)
    tools_by_category = defaultdict(list)
    for installed_tool in installed_tools:
        tool_info = get_tool_info(whitelist, installed_tool.name)
        if not tool_info:
            continue

        is_course_navigation = hasattr(installed_tool, "course_navigation")

        if tool_info.get("is_launchable", False):
            if is_course_navigation:
                sessionless_launch_url = installed_tool.get_sessionless_launch_url(
                    launch_type="course_navigation"
                )
            else:
                sessionless_launch_url = installed_tool.get_sessionless_launch_url()
        else:
            sessionless_launch_url = None

        tool_info.update(
            {
                "id": installed_tool.id,
                "lti_course_navigation": is_course_navigation,
                "sessionless_launch_url": sessionless_launch_url,
                "screenshot": "screenshots/" + tool_info["screenshot"],
            }
        )

        tools_by_category[tool_info.get("category", "Uncategorized")].append(tool_info)

    for category, tools in tools_by_category.items():
        # Determine tool order based on order in whitelist
        order = {
            tool.get("display_name"): i for i, tool in enumerate(whitelist[category])
        }
        tools_by_category[category] = sorted(
            tools, key=lambda k: order[k["display_name"]]
        )

    return tools_by_category, list(whitelist.keys())


def slugify(value):
    """
    Convert spaces to hyphens.
    Remove characters that aren't alphanumerics, underscores, or hyphens.
    Convert to lowercase.
    Also strip leading and trailing whitespace.

    From Django's "django/utils/text.py".
    """
    value = str(value)
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)
