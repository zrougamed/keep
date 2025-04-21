from pydantic import BaseModel, Field, ValidationError, root_validator
from typing import List, Dict, Union, Optional, Any, Literal, Type, cast
from enum import Enum

from keep.functions import cyaml
from keep.api.models.provider import Provider


class IncidentEventEnum(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    RESOLVED = "resolved"
    # Add other event types as needed


class EnrichKeyValue(BaseModel):
    key: str
    value: str


class EnrichDisposableKeyValue(BaseModel):
    key: str
    value: str
    disposable: Optional[bool] = None


# With schema for provider parameters
class WithSchema(BaseModel):
    enrich_alert: Optional[List[EnrichDisposableKeyValue]] = None
    enrich_incident: Optional[List[EnrichKeyValue]] = None
    # Additional fields would be dynamically added based on provider params


# Triggers
class ManualTrigger(BaseModel):
    type: Literal["manual"]


class AlertTrigger(BaseModel):
    type: Literal["alert"]
    filters: List[Dict[str, str]]


class IntervalTrigger(BaseModel):
    type: Literal["interval"]
    value: Union[str, int]


class IncidentTrigger(BaseModel):
    type: Literal["incident"]
    events: List[IncidentEventEnum]


TriggerModel = Union[ManualTrigger, AlertTrigger, IntervalTrigger, IncidentTrigger]


# Provider schemas
class YamlProviderBase(BaseModel):
    type: str
    with_: WithSchema = Field(alias="with")


# This would be dynamically generated for each provider
class YamlProviderSchema(YamlProviderBase):
    config: Optional[str] = None


# Condition schemas
class YamlThresholdCondition(BaseModel):
    id: Optional[str] = None
    name: str
    alias: Optional[str] = None
    type: Literal["threshold"]
    value: str
    compare_to: str
    level: Optional[str] = None


class YamlAssertCondition(BaseModel):
    id: Optional[str] = None
    name: str
    alias: Optional[str] = None
    type: Literal["assert"]
    assert_: str = Field(alias="assert")


ConditionModel = Union[YamlThresholdCondition, YamlAssertCondition]


# Step/Action schema
class YamlStepOrAction(BaseModel):
    name: str
    provider: YamlProviderSchema
    id: Optional[str] = None
    if_: Optional[str] = Field(alias="if", default=None)
    vars: Optional[Dict[str, str]] = None
    condition: Optional[List[ConditionModel]] = None
    foreach: Optional[str] = None


# Workflow input schema
class WorkflowInput(BaseModel):
    name: str
    type: str
    description: Optional[str] = None
    default: Optional[Any] = None
    required: Optional[bool] = None
    options: Optional[List[str]] = None
    visuallyRequired: Optional[bool] = None


# Main workflow schema
class YamlWorkflow(BaseModel):
    id: str
    disabled: Optional[bool] = None
    name: Optional[str] = None
    description: Optional[str] = None
    owners: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    services: Optional[List[str]] = None
    steps: Optional[List[YamlStepOrAction]] = None
    actions: Optional[List[YamlStepOrAction]] = None
    triggers: List[TriggerModel]
    consts: Optional[Dict[str, str]] = None
    inputs: Optional[List[WorkflowInput]] = None

    @root_validator
    def validate_either_steps_or_actions(cls, values):
        steps = values.get("steps")
        actions = values.get("actions")

        if (steps is None or len(steps) == 0) and (
            actions is None or len(actions) == 0
        ):
            raise ValueError(
                "Either 'steps' or 'actions' must be provided and not empty"
            )

        return values


# The overall schema
class YamlWorkflowDefinition(BaseModel):
    workflow: YamlWorkflow


def get_yaml_provider_schema(
    provider: Provider, schema_type: Literal["step", "action"]
) -> Type[BaseModel]:
    """
    Generate a dynamic provider schema based on provider capabilities.

    Args:
        provider: Provider instance
        schema_type: Either "step" for query operations or "action" for notify operations
    """
    # Get valid parameter keys from the provider
    valid_params = (
        provider.query_params if schema_type == "step" else provider.notify_params
    )
    valid_params = valid_params or []

    # Create a dynamic WithSchema for this provider
    with_fields = {}
    for param in valid_params:
        if param != "kwargs":
            with_fields[param] = (
                Optional[Union[str, int, bool, Dict[str, Any], List[Any]]],
                None,
            )

    # Add enrichment fields
    with_fields["enrich_alert"] = (Optional[List[EnrichDisposableKeyValue]], None)
    with_fields["enrich_incident"] = (Optional[List[EnrichKeyValue]], None)

    # Create the dynamic WithSchema class
    dynamic_with_schema = type(
        f"With{provider.type.capitalize()}Schema", (BaseModel,), with_fields
    )

    # Determine if config is required
    config_field = (
        (str, ...)  # Required field
        if getattr(provider, "webhook_required", False)
        else (Optional[str], None)  # Optional field
    )

    # Create the dynamic provider schema class
    provider_schema_fields = {
        "type": (
            Literal[provider.type],
            ...,
        ),  # Use Literal with the specific provider type
        "with_": (dynamic_with_schema, Field(alias="with")),
        "config": config_field,
    }

    provider_schema = type(
        f"YamlProvider{provider.type.capitalize()}",
        (BaseModel,),
        provider_schema_fields,
    )

    return provider_schema


def get_yaml_workflow_definition_schema(
    providers: List[Provider], partial: bool = False
) -> Type[YamlWorkflowDefinition]:
    """
    Generate a dynamic workflow definition schema based on available providers.

    Args:
        providers: List of available providers
        partial: If True, makes certain fields optional for partial validation
    """
    # Add mock provider to the list
    mock_provider = Provider(
        type="mock",
        display_name="Mock",
        tags=[],
        can_query=True,
        can_notify=True,
        query_params=[],
        notify_params=[],
        config={},
        installed=False,
        linked=False,
        last_alert_received="",
        details={"authentication": {}},
        pulling_available=False,
        validatedScopes={},
        pulling_enabled=False,
        categories=[],
        coming_soon=False,
        health=False,
    )

    providers_list = providers if providers is not None else []
    providers_with_mock = [mock_provider] + list(providers_list)
    unique_providers = []
    seen_types = set()

    for provider in providers_with_mock:
        if provider.type not in seen_types:
            unique_providers.append(provider)
            seen_types.add(provider.type)

    # Generate provider schemas for steps (query operations)
    step_provider_schemas = [
        get_yaml_provider_schema(provider, "step")
        for provider in unique_providers
        if provider.can_query
    ] or [YamlProviderSchema]

    # Generate provider schemas for actions (notify operations)
    action_provider_schemas = [
        get_yaml_provider_schema(provider, "action")
        for provider in unique_providers
        if provider.can_notify
    ] or [YamlProviderSchema]

    # Update YamlStepOrAction model to use provider schemas
    class DynamicYamlStepOrAction(YamlStepOrAction):
        provider: Union[YamlProviderSchema, YamlProviderBase] = Field(
            discriminator="type"
        )

    class DynamicYamlAction(YamlStepOrAction):
        provider: Union[YamlProviderSchema, YamlProviderBase] = Field(
            discriminator="type"
        )

    # Register the provider schemas with Pydantic
    for schema in step_provider_schemas:
        DynamicYamlStepOrAction.update_forward_refs(**{schema.__name__: schema})

    for schema in action_provider_schemas:
        DynamicYamlAction.update_forward_refs(**{schema.__name__: schema})

    # Create the base workflow model
    class DynamicYamlWorkflow(YamlWorkflow):
        steps: Optional[List[DynamicYamlStepOrAction]] = None
        actions: Optional[List[DynamicYamlAction]] = None

        @root_validator
        def validate_either_steps_or_actions(cls, values):
            steps = values.get("steps")
            actions = values.get("actions")

            if (
                not partial
                and (steps is None or len(steps) == 0)
                and (actions is None or len(actions) == 0)
            ):
                raise ValueError(
                    "Either 'steps' or 'actions' must be provided and not empty"
                )

            return values

    if partial:

        class PartialDynamicYamlWorkflow(DynamicYamlWorkflow):
            name: Optional[str] = None
            description: Optional[str] = None

    # Create the final workflow definition model
    class DynamicYamlWorkflowDefinition(YamlWorkflowDefinition):
        workflow: DynamicYamlWorkflow if not partial else PartialDynamicYamlWorkflow

    return cast(Type[YamlWorkflowDefinition], DynamicYamlWorkflowDefinition)


def validate_workflow_yaml(
    yaml_content: str, providers: List[Provider] = None, partial: bool = False
) -> YamlWorkflowDefinition:
    """
    Validate workflow YAML content against the schema.

    Args:
        yaml_content: YAML string to validate
        providers: Optional list of providers to validate against
        partial: If True, allows partial workflow validation
    """
    try:
        # Parse YAML into Python dict
        parsed_yaml = cyaml.safe_load(yaml_content)

        # Get the appropriate schema based on providers
        if providers is not None:
            schema_class = get_yaml_workflow_definition_schema(providers, partial)
        else:
            schema_class = YamlWorkflowDefinition

        # Validate against schema
        validated_workflow = schema_class(**parsed_yaml)
        return validated_workflow

    except cyaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {str(e)}")

    except ValidationError as e:
        raise ValueError(f"Validation error: {e}")


def test_validate_workflow_yaml():
    # Example usage
    try:
        with open("../../../examples/workflows/console_example.yml", "r") as file:
            yaml_content = file.read()

        # Get providers from factory
        from keep.providers.providers_factory import ProvidersFactory

        providers = ProvidersFactory.get_all_providers()

        validated_workflow = validate_workflow_yaml(yaml_content, providers)
        print(validated_workflow.json(indent=2))

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_validate_workflow_yaml()
