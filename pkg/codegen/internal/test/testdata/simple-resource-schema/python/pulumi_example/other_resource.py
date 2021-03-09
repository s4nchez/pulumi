# coding=utf-8
# *** WARNING: this file was generated by test. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities, _tables
from .resource import Resource

__all__ = ['OtherResourceArgs', 'OtherResource']

@pulumi.input_type
class OtherResourceArgs:
    def __init__(__self__, *,
                 foo: Optional[pulumi.Input['Resource']] = None):
        """
        The set of arguments for constructing a OtherResource resource.
        """
        if foo is not None:
            pulumi.set(__self__, "foo", foo)

    @property
    @pulumi.getter
    def foo(self) -> Optional[pulumi.Input['Resource']]:
        return pulumi.get(self, "foo")

    @foo.setter
    def foo(self, value: Optional[pulumi.Input['Resource']]):
        pulumi.set(self, "foo", value)


class OtherResource(pulumi.ComponentResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: Optional[OtherResourceArgs] = None,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        Create a OtherResource resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param OtherResourceArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 foo: Optional[pulumi.Input['Resource']] = None,
                 __props__=None,
                 __name__=None,
                 __opts__=None):
        """
        Create a OtherResource resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(OtherResourceArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 foo: Optional[pulumi.Input['Resource']] = None,
                 __props__=None,
                 __name__=None,
                 __opts__=None):
        if __name__ is not None:
            warnings.warn("explicit use of __name__ is deprecated", DeprecationWarning)
            resource_name = __name__
        if __opts__ is not None:
            warnings.warn("explicit use of __opts__ is deprecated, use 'opts' instead", DeprecationWarning)
            opts = __opts__
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is not None:
            raise ValueError('ComponentResource classes do not support opts.id')
        else:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = dict()

            __props__['foo'] = foo
        super(OtherResource, __self__).__init__(
            'example::OtherResource',
            resource_name,
            __props__,
            opts,
            remote=True)

    @property
    @pulumi.getter
    def foo(self) -> pulumi.Output[Optional['Resource']]:
        return pulumi.get(self, "foo")

    def translate_output_property(self, prop):
        return _tables.CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return _tables.SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop

