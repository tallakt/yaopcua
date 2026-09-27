defmodule OPCUA.Server.Node do
  @moduledoc """
  A node of a server's address space.

  `class` is `:object`, `:variable`, `:method`, `:object_type`,
  `:variable_type`, `:reference_type`, `:data_type` or `:view`. `references`
  holds each reference as `{reference_type, target, forward?}`, in both
  directions. `attributes` holds the attributes of the class, such as
  `:data_type`, `:value_rank` and `:access_level` for a variable. A
  variable's value is kept apart, so it can change without touching the node.
  """

  defstruct [
    :node_id,
    :class,
    :browse_name,
    :display_name,
    description: nil,
    attributes: %{},
    references: []
  ]

  @type ref :: {OPCUA.NodeId.t(), OPCUA.NodeId.t(), boolean}

  @type t :: %__MODULE__{
          node_id: OPCUA.NodeId.t(),
          class:
            :object
            | :variable
            | :method
            | :object_type
            | :variable_type
            | :reference_type
            | :data_type
            | :view,
          browse_name: OPCUA.QualifiedName.t(),
          display_name: OPCUA.LocalizedText.t(),
          description: OPCUA.LocalizedText.t() | nil,
          attributes: map,
          references: [ref]
        }
end
