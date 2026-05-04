defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.15"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
