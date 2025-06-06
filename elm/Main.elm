port module Main exposing (..)

import Browser
import Browser.Dom exposing (..)
import Browser.Navigation as Nav
import Email
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (..)
import Http exposing (..)
import Json.Decode exposing (..)
import Json.Encode
import List exposing (..)
import Regex
import String exposing (..)
import Task
import Url
import Url.Builder



-- REGEX


nameRegex : Regex.Regex
nameRegex =
    Maybe.withDefault Regex.never (Regex.fromString "^[a-zA-Z-'\\. ]+$")



-- STRINGS


firstNameFieldName : String
firstNameFieldName =
    "firstName"


lastNameFieldName : String
lastNameFieldName =
    "lastName"


emailAddressFieldName : String
emailAddressFieldName =
    "emailAddress"


serverDataFieldName : String
serverDataFieldName =
    "serverData"


localDataFieldName : String
localDataFieldName =
    "localData"



-- TYPES


type NextAction
    = CheckAvailability
    | NoOpNextAction


type ValidationResult
    = Valid
    | Invalid String


type FormState
    = Editing
    | Submitting


type alias CheckAvailabilityResult =
    { available : Maybe Bool }


type alias Model =
    { firstName : String
    , lastName : String
    , emailAddress : String
    , checkAvailabilityResult : Maybe (Result Http.Error CheckAvailabilityResult)
    , showValidation : Bool
    , formState : FormState
    , nextAction : NextAction
    }


type Msg
    = UrlRequest Browser.UrlRequest
    | UrlChanged Url.Url
    | FormSubmitted
    | FormChanged
    | FirstNameInput String
    | LastNameInput String
    | EmailAddressInput String
    | LocalStorageSaved Bool
    | CheckAvailabilityResultReceived (Result Http.Error CheckAvailabilityResult)
    | NoOpMsg



-- PLUMBING


main : Program Value Model Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = UrlRequest
        }


init : Value -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init flags url key =
    ( buildInitialModel flags
    , Cmd.none
    )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UrlRequest urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.load (Url.toString url) )

                Browser.External href ->
                    ( model, Nav.load href )

        UrlChanged url ->
            ( model, Cmd.none )

        FormSubmitted ->
            ( { model
                | showValidation = True
                , formState =
                    case validateModel model of
                        Invalid _ ->
                            Editing

                        Valid ->
                            Submitting
                , nextAction =
                    case validateModel model of
                        Invalid _ ->
                            NoOpNextAction

                        Valid ->
                            CheckAvailability
              }
            , case validateModel model of
                Invalid fieldId ->
                    Task.attempt (\_ -> NoOpMsg) (focus fieldId)

                Valid ->
                    saveToLocalStorage (stringifyModel model)
            )

        FormChanged ->
            ( { model | nextAction = NoOpNextAction }, saveToLocalStorage (stringifyModel model) )

        FirstNameInput firstName ->
            ( { model
                | firstName = firstName
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        LastNameInput lastName ->
            ( { model
                | lastName = lastName
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        EmailAddressInput emailAddress ->
            ( { model
                | emailAddress = emailAddress
                , checkAvailabilityResult = Nothing
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        NoOpMsg ->
            ( { model | nextAction = NoOpNextAction }, Cmd.none )

        LocalStorageSaved _ ->
            ( { model | nextAction = NoOpNextAction }
            , case model.nextAction of
                CheckAvailability ->
                    checkAvailability model.emailAddress

                NoOpNextAction ->
                    Cmd.none
            )

        CheckAvailabilityResultReceived result ->
            ( { model
                | nextAction = NoOpNextAction
                , checkAvailabilityResult = Just result
                , formState =
                    case result of
                        Ok availabilityResult ->
                            case availabilityResult.available of
                                Just True ->
                                    Submitting

                                _ ->
                                    Editing

                        Err _ ->
                            Editing
              }
            , case result of
                Ok availabilityResult ->
                    case availabilityResult.available of
                        Just True ->
                            submitForm True

                        _ ->
                            Task.attempt (\_ -> NoOpMsg) (focus "email_address")

                Err _ ->
                    Task.attempt (\_ -> NoOpMsg) (focus "email_address")
            )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.batch
        [ localStorageSaved LocalStorageSaved
        ]


view : Model -> Browser.Document Msg
view model =
    let
        firstNameValidationResult : ValidationResult
        firstNameValidationResult =
            validateName "first" model.firstName

        lastNameValidationResult : ValidationResult
        lastNameValidationResult =
            validateName "last" model.lastName

        emailAddressValidationResult : ValidationResult
        emailAddressValidationResult =
            validateEmailAddress model.emailAddress model.checkAvailabilityResult
    in
    { title = "Google Workspace Onboarding"
    , body =
        [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
            [ h1 []
                [ text "Google Workspace Onboarding"
                ]
            , p [ class "mt-4", class "mb-4" ]
                [ text "RoboJackets uses "
                , a [ href "https://workspace.google.com", target "_blank" ]
                    [ text "Google Workspace"
                    ]
                , text " for business email and collaboration tools. Request a Google Workspace account below."
                ]
            , Html.form
                [ class "row"
                , class "g-3"
                , method "POST"
                , action "/"
                , novalidate True
                , onSubmit FormSubmitted
                ]
                [ div [ class "col-6" ]
                    [ label [ for "first_name", class "form-label" ]
                        [ text "First Name" ]
                    , input
                        [ id "first_name"
                        , type_ "text"
                        , classList
                            [ ( "form-control", True )
                            , ( "is-valid", model.showValidation && isValid firstNameValidationResult )
                            , ( "is-invalid", model.showValidation && not (isValid firstNameValidationResult) )
                            ]
                        , name "first_name"
                        , minlength 1
                        , maxlength 60
                        , required True
                        , readonly (model.formState /= Editing)
                        , placeholder "First Name"
                        , on "change" (succeed FormChanged)
                        , onInput FirstNameInput
                        , Html.Attributes.value model.firstName
                        ]
                        []
                    , div [ class "invalid-feedback" ]
                        [ text (feedbackText firstNameValidationResult) ]
                    ]
                , div [ class "col-6" ]
                    [ label [ for "last_name", class "form-label" ]
                        [ text "Last Name" ]
                    , input
                        [ id "last_name"
                        , type_ "text"
                        , classList
                            [ ( "form-control", True )
                            , ( "is-valid", model.showValidation && isValid lastNameValidationResult )
                            , ( "is-invalid", model.showValidation && not (isValid lastNameValidationResult) )
                            ]
                        , name "last_name"
                        , minlength 1
                        , maxlength 60
                        , required True
                        , readonly (model.formState /= Editing)
                        , placeholder "Last Name"
                        , on "change" (succeed FormChanged)
                        , onInput LastNameInput
                        , Html.Attributes.value model.lastName
                        ]
                        []
                    , div [ class "invalid-feedback" ]
                        [ text (feedbackText lastNameValidationResult) ]
                    ]
                , div [ class "form-text", class "mb-3" ]
                    [ text "Your name will be visible to other RoboJackets members and external contacts." ]
                , div [ class "col-12" ]
                    [ label [ for "email_address", class "form-label" ]
                        [ text "Email Address" ]
                    , input
                        [ id "email_address"
                        , name "email_address"
                        , type_ "email"
                        , classList
                            [ ( "form-control", True )
                            , ( "is-valid", model.showValidation && isValid emailAddressValidationResult )
                            , ( "is-invalid", model.showValidation && not (isValid emailAddressValidationResult) )
                            ]
                        , minlength 21
                        , required True
                        , readonly (model.formState /= Editing)
                        , placeholder "Email Address"
                        , on "change" (succeed FormChanged)
                        , onInput EmailAddressInput
                        , Html.Attributes.value model.emailAddress
                        ]
                        []
                    , div [ class "invalid-feedback" ]
                        [ text (feedbackText emailAddressValidationResult) ]
                    ]
                , div [ class "form-text", class "mb-3" ]
                    [ text "Your email address should include your first and last name seperated by a period." ]
                , div [ class "col-12", class "mb-2" ]
                    [ button
                        [ type_ "submit"
                        , class "btn"
                        , class "btn-primary"
                        , id "submit_button"
                        , disabled (model.formState /= Editing)
                        ]
                        [ text "Create Account"
                        ]
                    ]
                ]
            , div [ class "mb-4", class "mb-md-5", class "col-12", class "form-text" ]
                [ text "By creating an account, you confirm that you have read and acknowlege the "
                , a [ href "https://policies.google.com/terms", class "text-secondary", target "_blank" ] [ text "Google Terms of Service" ]
                , text ", "
                , a [ href "https://policies.google.com/privacy", class "text-secondary", target "_blank" ] [ text "Google Privacy Policy" ]
                , text ", "
                , a [ href "https://support.google.com/accounts/answer/181692", class "text-secondary", target "_blank" ] [ text "Google Workspace Data Access Notice" ]
                , text ", "
                , a [ href "https://cloud.google.com/terms/cloud-privacy-notice", class "text-secondary", target "_blank" ] [ text "Google Cloud Privacy Notice" ]
                , text ", "
                , a [ href "https://legal.hubspot.com/terms-of-service", class "text-secondary", target "_blank" ] [ text "HubSpot Customer Terms of Service" ]
                , text ", "
                , a [ href "https://legal.hubspot.com/privacy-policy", class "text-secondary", target "_blank" ] [ text "HubSpot Privacy Policy" ]
                , text ", "
                , a [ href "https://policylibrary.gatech.edu/information-technology/acceptable-use-policy", class "text-secondary", target "_blank" ] [ text "Georgia Institute of Technology Acceptable Use Policy" ]
                , text ", "
                , a [ href "https://policylibrary.gatech.edu/information-technology/cyber-security-policy", class "text-secondary", target "_blank" ] [ text "Georgia Institute of Technology Cyber Security Policy" ]
                , text ", and "
                , a [ href "https://policylibrary.gatech.edu/information-technology/data-privacy-policy", class "text-secondary", target "_blank" ] [ text "Georgia Institute of Technology Data Privacy Policy" ]
                , text ". You further acknowledge that your Google Workspace account is provided to you for official use only, and you have no expectation of privacy while using your account."
                ]
            ]
        ]
    }



-- VALIDATION


validateName : String -> String -> ValidationResult
validateName whichName nameValue =
    if blankString nameValue then
        Invalid ("Please enter your " ++ whichName ++ " name")

    else if String.length (String.trim nameValue) < 2 then
        Invalid ("Your " ++ whichName ++ " name must be at least 2 characters")

    else if String.length (String.trim nameValue) > 60 then
        Invalid ("Your " ++ whichName ++ " name may be a maximum of 60 characters")

    else if not (Regex.contains nameRegex nameValue) then
        Invalid ("Your " ++ whichName ++ " name may only contain letters, spaces, dashes, apostrophes, and periods")

    else
        Valid


validateEmailAddress : String -> Maybe (Result Http.Error CheckAvailabilityResult) -> ValidationResult
validateEmailAddress emailAddress maybeCheckAvailabilityResult =
    case Email.parse (String.toLower emailAddress) of
        Ok addressParts ->
            if addressParts.domain == "robojackets.org" then
                if List.length (split "." addressParts.local) /= 2 then
                    Invalid "Your email address should include your first and last name separated by a period"

                else if String.length (Maybe.withDefault "" (List.head (split "." addressParts.local))) < 2 then
                    Invalid "Your first name must be at least 2 characters"

                else if String.length (Maybe.withDefault "" (List.head (List.drop 1 (split "." addressParts.local)))) < 2 then
                    Invalid "Your last name must be at least 2 characters"

                else if String.length addressParts.local > 60 then
                    Invalid "Your email address may be a maximum of 60 characters followed by @robojackets.org"

                else
                    case validateName "" addressParts.local of
                        Invalid _ ->
                            Invalid "Your email address may only contain letters, dashes, and periods"

                        Valid ->
                            case maybeCheckAvailabilityResult of
                                Just checkAvailabilityResult ->
                                    case checkAvailabilityResult of
                                        Ok result ->
                                            case result.available of
                                                Just True ->
                                                    Valid

                                                Just False ->
                                                    Invalid "This email address isn't available — if you'd like to use it, please ask in #it-helpdesk"

                                                Nothing ->
                                                    Invalid "There was an error confirming this email address is available"

                                        Err _ ->
                                            Invalid "There was an error confirming this email address is available"

                                Nothing ->
                                    Valid

            else
                Invalid "Your email address must end in @robojackets.org"

        Err _ ->
            Invalid "Please enter a valid email address"


validateModel : Model -> ValidationResult
validateModel model =
    if not (isValid (validateName "first" model.firstName)) then
        Invalid "first_name"

    else if not (isValid (validateName "last" model.lastName)) then
        Invalid "last_name"

    else if not (isValid (validateEmailAddress model.emailAddress model.checkAvailabilityResult)) then
        Invalid "email_address"

    else
        Valid



-- HELPERS


isValid : ValidationResult -> Bool
isValid validation =
    case validation of
        Valid ->
            True

        Invalid _ ->
            False


feedbackText : ValidationResult -> String
feedbackText validation =
    case validation of
        Valid ->
            ""

        Invalid text ->
            text


stringifyModel : Model -> String
stringifyModel model =
    Json.Encode.encode 0
        (Json.Encode.object
            [ ( firstNameFieldName, Json.Encode.string (String.trim model.firstName) )
            , ( lastNameFieldName, Json.Encode.string (String.trim model.lastName) )
            , ( emailAddressFieldName, Json.Encode.string (String.trim model.emailAddress) )
            ]
        )


checkAvailability : String -> Cmd Msg
checkAvailability emailAddress =
    Http.post
        { url =
            Url.Builder.absolute
                [ "check-availability" ]
                []
        , body =
            jsonBody
                (Json.Encode.object
                    [ ( "emailAddress", Json.Encode.string (String.trim emailAddress) )
                    ]
                )
        , expect = expectJson CheckAvailabilityResultReceived checkAvailabilityResultDecoder
        }


checkAvailabilityResultDecoder : Decoder CheckAvailabilityResult
checkAvailabilityResultDecoder =
    Json.Decode.map CheckAvailabilityResult
        (maybe (at [ "available" ] Json.Decode.bool))


buildInitialModel : Value -> Model
buildInitialModel value =
    let
        serverDataEmailAddress : String
        serverDataEmailAddress =
            Result.withDefault "" (decodeValue (at [ serverDataFieldName, emailAddressFieldName ] string) value)
    in
    Model
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, firstNameFieldName ] string) value))
                (decodeString (field firstNameFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, lastNameFieldName ] string) value))
                (decodeString (field lastNameFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                serverDataEmailAddress
                (decodeString (field emailAddressFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        Nothing
        False
        Editing
        NoOpNextAction


nonBlankString : String -> Bool
nonBlankString value =
    not (blankString value)


blankString : String -> Bool
blankString value =
    String.isEmpty (String.trim value)



-- PORTS


port submitForm : Bool -> Cmd msg


port saveToLocalStorage : String -> Cmd msg


port localStorageSaved : (Bool -> msg) -> Sub msg
