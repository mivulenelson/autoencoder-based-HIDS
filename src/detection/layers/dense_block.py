import tensorflow as tf
from tensorflow.keras import layers


@tf.keras.utils.register_keras_serializable(package="HIDS")
class DetectionBlock(layers.Layer):
    """
    Dense + BatchNorm + Dropout block, architecturally equivalent to the
    inline encoder blocks training.ipynb currently builds by hand.

    Args:
        units:        Number of neurons in the Dense layer.
        dropout_rate: Fraction of units to drop during training (default 0.10,
                      matching training.ipynb Section 5's dropout value).
        **kwargs:     Passed through to the parent Layer (e.g. name=).

    Example:
        x = DetectionBlock(16, dropout_rate=0.10, name="enc_1")(inputs, training=True)
        x = DetectionBlock(8,  dropout_rate=0.10, name="enc_2")(x,      training=True)
    """

    def __init__(self, units: int, dropout_rate: float = 0.10, **kwargs):
        super().__init__(**kwargs)

        # Store scalar hyperparameters for get_config() serialisation
        self.units        = units
        self.dropout_rate = dropout_rate   # scalar float — NOT overwritten below

        # Sub-layers — each stored under a distinct attribute name
        self.dense   = layers.Dense(units, activation="relu")
        self.bn      = layers.BatchNormalization()
        self.dropout = layers.Dropout(dropout_rate)

    # ------------------------------------------------------------------
    # Forward pass
    # ------------------------------------------------------------------

    def call(self, inputs, training: bool = False):
        """
        Args:
            inputs:   Input tensor.
            training: Pass True during training so Dropout and BatchNorm
                      behave correctly; False (default) at inference time.
        """
        x = self.dense(inputs)
        x = self.bn(x, training=training)      # BN uses running stats at inference
        x = self.dropout(x, training=training) # Dropout is a no-op at inference
        return x

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def get_config(self) -> dict:
        """
        Returns the layer config so Keras can reconstruct it from a saved
        .keras archive. Called by model.save() and load_model().
        """
        config = super().get_config()
        config.update({
            "units"       : self.units,
            "dropout_rate": self.dropout_rate,
        })
        return config

    @classmethod
    def from_config(cls, config: dict) -> "DetectionBlock":
        return cls(**config)